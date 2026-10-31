#!/bin/sh
# build-image.sh — HomeSteadyLink flashable image (§F1).
# Stock Armbian Ubuntu 24.04 (orangepizero2w) + injected /opt/homesteadlink
# payload + enabled systemd units -> ONE .img.xz.
# Injection: loop-mount (root) preferred; if the host has no loop devices
# (e.g. a container VM whose kernel lacks the loop module), falls back to
# debugfs(8) writes into the extracted ext4 root partition — same result.
# Env overrides: ARMBIAN_URL, ARMBIAN_IMG_XZ, GO, OUT_DIR, SKIP_DOWNLOAD=1.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FW=$(dirname "$HERE")
OUT_DIR=${OUT_DIR:-"$HERE/out"}
WORK=${WORK:-"$HERE/work"}
ARMBIAN_URL=${ARMBIAN_URL:-"https://archive.armbian.com/orangepizero2w/archive/Armbian_25.5.1_Orangepizero2w_noble_current_6.12.23.img.xz"}
mkdir -p "$OUT_DIR" "$WORK"
log() { echo "[build-image] $*"; }
fail() { echo "[build-image] FAIL: $*" >&2; exit 1; }

# --- 1. daemon binary (arm64, static, no cgo) ---
BIN="$WORK/hsl-provisiond"
if [ -n "${GO:-}" ] || command -v go >/dev/null 2>&1; then
  GO=${GO:-go}
  log "building hsl-provisiond with $GO"
  ( cd "$FW/hsl-provisiond" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$GO" build -trimpath -o "$BIN" . )
elif [ -f "$FW/hsl-provisiond/hsl-provisiond" ]; then
  log "no Go toolchain: using prebuilt $FW/hsl-provisiond/hsl-provisiond"
  cp "$FW/hsl-provisiond/hsl-provisiond" "$BIN"
else
  fail "no Go toolchain and no prebuilt daemon binary"
fi
file "$BIN" | grep -q "ARM aarch64" || fail "daemon binary is not aarch64: $(file "$BIN")"
log "daemon: $(file "$BIN") size=$(stat -c %s "$BIN")"

# --- 2. stock image ---
IMG_XZ=${ARMBIAN_IMG_XZ:-"$WORK/armbian.img.xz"}
if [ "${SKIP_DOWNLOAD:-0}" != "1" ] || [ ! -s "$IMG_XZ" ]; then
  log "downloading $ARMBIAN_URL"
  curl -fL --retry 3 -o "$IMG_XZ" "$ARMBIAN_URL" || fail "Armbian download failed from $ARMBIAN_URL"
fi
# Checksum: verify when the publisher ships one next to the image (.sha).
SHA_URL="${ARMBIAN_URL}.sha"
if curl -fsSL -o "$WORK/downloaded.sha" "$SHA_URL" 2>/dev/null; then
  EXPECTED=$(grep -oE '^[a-f0-9]{64}' "$WORK/downloaded.sha" | head -1 || true)
  if [ -n "${EXPECTED:-}" ]; then
    ACTUAL=$(sha256sum "$IMG_XZ" | awk '{print $1}')
    [ "$EXPECTED" = "$ACTUAL" ] || fail "checksum mismatch: expected $EXPECTED got $ACTUAL"
    log "checksum OK $ACTUAL"
  else
    log "checksum file present but no hash parsed; continuing unverified"
  fi
else
  log "no published checksum at $SHA_URL; continuing unverified"
fi

IMG="$WORK/armbian.img"
log "decompressing stock image"
xz -dkf "$IMG_XZ"
DECOMPRESSED="$(dirname "$IMG_XZ")/$(basename "$IMG_XZ" .xz)"
if [ "$DECOMPRESSED" != "$IMG" ]; then mv -f "$DECOMPRESSED" "$IMG"; fi
[ -f "$IMG" ] || fail "decompressed image not found at $IMG"

MODE=""
if LOOP=$(losetup --find --show --partscan "$IMG" 2>/dev/null) && [ -n "${LOOP:-}" ]; then
  MODE="loop"
elif command -v debugfs >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  MODE="debugfs"
  losetup -d "$LOOP" 2>/dev/null || true
  log "no loop device available on this host; using debugfs injection fallback"
else
  fail "no loop device and no debugfs fallback available"
fi
log "injection mode: $MODE"

if [ "$MODE" = "loop" ]; then
  [ "$(id -u)" = "0" ] || fail "loop mode must run as root"
  cleanup() {
    mountpoint -q "$WORK/mnt" && umount "$WORK/mnt" || true
    [ -n "${LOOP:-}" ] && losetup -d "$LOOP" || true
  }
  trap cleanup EXIT INT TERM
  mkdir -p "$WORK/mnt"
  ROOTPART=$(ls "${LOOP}"p* | tail -1)
  mount "$ROOTPART" "$WORK/mnt"
  ROOT="$WORK/mnt"
  [ -d "$ROOT/etc" ] || fail "mounted partition does not look like a rootfs"
else
  # Extract the root (last) partition; parse MBR/GPT with python3.
  PARTINFO=$(python3 - "$IMG" <<'PYEOF'
import struct, sys
d = open(sys.argv[1], 'rb')
d.seek(512)
gpt_hdr = d.read(8)
d.seek(0)
mbr = d.read(512)
parts = []
if mbr[510:512] == b'\x55\xaa' and mbr[446+4] == 0xEE and gpt_hdr.startswith(b'EFI PART'):
    d.seek(512)
    hdr = d.read(512)
    part_lba, = struct.unpack_from('<Q', hdr, 72)
    count, = struct.unpack_from('<I', hdr, 80)
    size, = struct.unpack_from('<I', hdr, 84)
    d.seek(part_lba * 512)
    entries = d.read(count * size)
    for i in range(count):
        e = entries[i*size:(i+1)*size]
        if e[:16] == b'\x00' * 16:
            continue
        first, last = struct.unpack_from('<QQ', e, 32)
        parts.append((first, last - first + 1))
else:
    for i in range(4):
        e = mbr[446+i*16:446+(i+1)*16]
        if e[4] != 0:
            start, sectors = struct.unpack_from('<II', e, 8)
            parts.append((start, sectors))
if not parts:
    sys.exit('no partitions found')
s, n = parts[-1]
print(f"{s} {n}")
PYEOF
) || fail "partition table parse failed"
  PSTART=$(echo "$PARTINFO" | awk '{print $1}')
  PSECTORS=$(echo "$PARTINFO" | awk '{print $2}')
  log "root partition: start sector $PSTART, $PSECTORS sectors"
  ROOTPART_IMG="$WORK/rootpart.img"
  dd if="$IMG" of="$ROOTPART_IMG" bs=512 skip="$PSTART" count="$PSECTORS" status=none
  ROOT="$WORK/rootfs-dump"
  mkdir -p "$ROOT/boot" "$ROOT/etc"
  # Dump /boot (recursively enough for config + dtb) for the assertions.
  # debugfs ls -p format: /inode/mode/uid/gid/name/size/ -> name is field 6.
  debugfs -R "ls -p /boot" "$ROOTPART_IMG" 2>/dev/null | awk -F/ '{print $6}' | grep -v '^$' > "$WORK/boot-list.txt" || true
  while IFS= read -r name; do
    case "$name" in
      config-*)
        [ -f "$ROOT/boot/$name" ] || debugfs -R "dump /boot/$name $ROOT/boot/$name" "$ROOTPART_IMG" >/dev/null 2>&1 || true
        ;;
    esac
  done < "$WORK/boot-list.txt"
  # DTBs live in /boot/dtb-<kver>-*/<vendor>/ (the /boot/dtb symlink target).
  DTBDIRS=$(grep '^dtb-' "$WORK/boot-list.txt" || true)
  for ddir in $DTBDIRS dtb; do
    for sub in allwinner rockchip sunxi ""; do
      subpath="/boot/$ddir${sub:+/$sub}"
      debugfs -R "ls -p $subpath" "$ROOTPART_IMG" 2>/dev/null | awk -F/ '{print $6}' | grep -v '^$' > "$WORK/dtb-list.txt" || true
      while IFS= read -r name; do
        case "$name" in
          *orangepi-zero2w*.dtb|*orangepi-zero-2w*.dtb)
            debugfs -R "dump $subpath/$name $ROOT/boot/$name" "$ROOTPART_IMG" >/dev/null 2>&1 || true
            ;;
        esac
      done < "$WORK/dtb-list.txt"
    done
  done
  debugfs -R "dump /boot/dtb/allwinner/sun50i-h618-orangepi-zero2w.dtb $ROOT/boot/sun50i-h618-orangepi-zero2w.dtb" "$ROOTPART_IMG" >/dev/null 2>&1 || true
fi

# --- 3. §F3 kernel config assertions (shared; $ROOT/boot holds the files) ---
KCFG=""
if [ "$MODE" = "loop" ]; then
  for cand in "$ROOT/boot/config-"* "$ROOT/usr/lib/modules/"*/config; do
    [ -f "$cand" ] && KCFG="$cand" && break
  done
  if [ -z "$KCFG" ]; then
    for kimg in "$ROOT/boot/Image" "$ROOT/boot/vmlinuz-"*; do
      if [ -f "$kimg" ] && command -v extract-ikconfig >/dev/null 2>&1; then
        extract-ikconfig "$kimg" > "$WORK/kconfig" 2>/dev/null && KCFG="$WORK/kconfig" && break
      fi
    done
  fi
else
  for cand in "$ROOT/boot/config-"*; do
    [ -f "$cand" ] && KCFG="$cand" && break
  done
fi
[ -n "$KCFG" ] || fail "no kernel config found in image - cannot run F3 assertions"
log "kernel config source: $KCFG"
MISSING=""
for sym in CONFIG_BT CONFIG_BT_HCIUART CONFIG_BT_HCIUART_H4 CONFIG_RFKILL \
           CONFIG_CFG80211 CONFIG_MAC80211 CONFIG_WIREGUARD CONFIG_TUN \
           CONFIG_USB_GADGET CONFIG_USB_CONFIGFS CONFIG_USB_CONFIGFS_ECM \
           CONFIG_USB_CONFIGFS_NCM CONFIG_USB_CONFIGFS_ACM CONFIG_NF_NAT CONFIG_NF_TABLES; do
  if ! grep -qE "^${sym}=(y|m)" "$KCFG"; then MISSING="$MISSING $sym"; fi
done
[ -z "$MISSING" ] || fail "kernel config misses (F3):$MISSING"
log "kernel config assertions passed (F3)"

# --- 4. §F2 DTB bluetooth assertion ---
if [ "$MODE" = "loop" ]; then
  DTB=$(ls "$ROOT/boot/dtb/"*/sun50i-h618-orangepi-zero2w.dtb "$ROOT/boot/dtb/sun50i-h618-orangepi-zero2w.dtb" 2>/dev/null | head -1 || true)
  [ -n "${DTB:-}" ] || DTB=$(find "$ROOT/boot" -name '*orangepi-zero2w*.dtb' 2>/dev/null | head -1 || true)
else
  DTB=$(ls "$ROOT/boot/"*orangepi-zero2w*.dtb 2>/dev/null | head -1 || true)
fi
[ -n "${DTB:-}" ] || fail "board DTB not found in shipped image"
# §F2 DT assertion result is recorded in $WORK/dt-assertion.txt either way.
# A miss does NOT abort this build (task decision 2026-11-01: §F3 kernel
# misses abort; the DT result is reported loudly) — but it is a real
# hardware blocker: without a bluetooth node / enabled BT UART, hci0 will
# not appear and BLE provisioning is dead on the board until a DT overlay
# enabling the BT UART (serial@5000400, sprdbt) is shipped.
DT_RESULT="FAIL"
if command -v dtc >/dev/null 2>&1; then
  dtc -I dtb -O dts "$DTB" > "$WORK/board.dts" 2>/dev/null || fail "dtc failed on $DTB"
  if grep -qi "bluetooth" "$WORK/board.dts"; then DT_RESULT="PASS (dtc method)"; fi
  DT_METHOD="dtc -I dtb -O dts"
else
  if grep -a -qi "bluetooth" "$DTB"; then DT_RESULT="PASS (raw-bytes method)"; fi
  grep -a -qi "sprdbt" "$DTB" || log "note: 'sprdbt' string not found in DTB (raw-bytes method)"
  DT_METHOD="raw-bytes grep on DTB (dtc unavailable)"
fi
echo "DT assertion (§F2): $DT_RESULT — method: $DT_METHOD — dtb: $DTB" > "$WORK/dt-assertion.txt"
if [ "${DT_RESULT#FAIL}" != "$DT_RESULT" ]; then
  log "FAIL-DT-ASSERTION: no bluetooth node in shipped DTB ($DT_METHOD) — recorded in dt-assertion.txt; building anyway, BT on hardware is BLOCKED until a BT-UART overlay ships"
else
  log "DTB bluetooth node asserted ($DT_RESULT)"
fi

# --- 5. inject payload ---
if [ "$MODE" = "loop" ]; then
  PAY="$ROOT/opt/homesteadlink"
  mkdir -p "$PAY/bin" "$PAY/configs" "$ROOT/etc/homesteadlink" "$ROOT/etc/systemd/system"
  install -m 0755 "$BIN" "$PAY/bin/hsl-provisiond"
  install -m 0755 "$FW/systemd/hsl-firstboot.sh" "$PAY/bin/hsl-firstboot.sh"
  install -m 0644 "$FW/systemd/hsl-bt-attach.service" "$FW/systemd/hsl-firstboot.service" "$FW/systemd/hsl-provisiond.service" "$ROOT/etc/systemd/system/"
  mkdir -p "$ROOT/etc/systemd/system/bluetooth.service.d"
  install -m 0644 "$FW/systemd/bluetooth.service.d/override.conf" "$ROOT/etc/systemd/system/bluetooth.service.d/override.conf"
  install -m 0644 "$FW/configs/nftables-hsl.nft" "$ROOT/etc/homesteadlink/nftables.conf"
  install -m 0644 "$FW/configs/"* "$PAY/configs/"
  if [ -f "$ROOT/etc/bluetooth/main.conf" ]; then
    grep -q "ControllerMode" "$ROOT/etc/bluetooth/main.conf" || cat "$FW/configs/bluetooth-main.conf" >> "$ROOT/etc/bluetooth/main.conf"
  else
    mkdir -p "$ROOT/etc/bluetooth"
    install -m 0644 "$FW/configs/bluetooth-main.conf" "$ROOT/etc/bluetooth/main.conf"
  fi
  mkdir -p "$ROOT/etc/dnsmasq.d"
  install -m 0644 "$FW/configs/dnsmasq-homesteadlink.conf" "$ROOT/etc/dnsmasq.d/homesteadlink.conf" || true
  enable_unit() {
    mkdir -p "$ROOT/etc/systemd/system/multi-user.target.wants"
    ln -sf "../$1" "$ROOT/etc/systemd/system/multi-user.target.wants/$1"
  }
  if command -v qemu-aarch64 >/dev/null 2>&1 || command -v qemu-aarch64-static >/dev/null 2>&1; then
    QEMU=$(command -v qemu-aarch64 || command -v qemu-aarch64-static)
    cp "$QEMU" "$ROOT/usr/bin/" 2>/dev/null || true
    QB=$(basename "$QEMU")
    if chroot "$ROOT" "/usr/bin/$QB" /bin/systemctl enable hsl-bt-attach.service hsl-firstboot.service hsl-provisiond.service bluetooth.service 2>/dev/null; then
      log "units enabled via qemu chroot systemctl"
    else
      log "qemu chroot systemctl failed; falling back to manual symlinks"
      enable_unit hsl-bt-attach.service; enable_unit hsl-firstboot.service; enable_unit hsl-provisiond.service
    fi
    rm -f "$ROOT/usr/bin/qemu-aarch64" "$ROOT/usr/bin/qemu-aarch64-static" 2>/dev/null || true
  else
    log "qemu-aarch64 unavailable; enabling units via manual symlinks"
    enable_unit hsl-bt-attach.service; enable_unit hsl-firstboot.service; enable_unit hsl-provisiond.service
  fi
  log "injected payload (loop mode)"
  sync
  umount "$WORK/mnt"
  losetup -d "$LOOP"; LOOP=""
  trap - EXIT INT TERM
else
  # debugfs injection: build a command file. debugfs continues past
  # per-command errors (e.g. mkdir of an existing dir) when fed with -f.
  CMDS="$WORK/debugfs.cmds"
  : > "$CMDS"
  dmkdir() { echo "mkdir $1" >> "$CMDS"; }
  dwrite() { # local_path dest mode-octal-with-type
    echo "write $1 $2" >> "$CMDS"
    echo "sif $2 mode $3" >> "$CMDS"
  }
  dmkdir /opt/homesteadlink
  dmkdir /opt/homesteadlink/bin
  dmkdir /opt/homesteadlink/configs
  dmkdir /etc/homesteadlink
  dmkdir /etc/systemd/system/bluetooth.service.d
  dmkdir /etc/bluetooth
  dmkdir /etc/dnsmasq.d
  dwrite "$BIN" /opt/homesteadlink/bin/hsl-provisiond 0100755
  dwrite "$FW/systemd/hsl-firstboot.sh" /opt/homesteadlink/bin/hsl-firstboot.sh 0100755
  for u in hsl-bt-attach.service hsl-firstboot.service hsl-provisiond.service; do
    dwrite "$FW/systemd/$u" "/etc/systemd/system/$u" 0100644
  done
  dwrite "$FW/systemd/bluetooth.service.d/override.conf" /etc/systemd/system/bluetooth.service.d/override.conf 0100644
  dwrite "$FW/configs/nftables-hsl.nft" /etc/homesteadlink/nftables.conf 0100644
  for c in "$FW/configs/"*; do
    dwrite "$c" "/opt/homesteadlink/configs/$(basename "$c")" 0100644
  done
  dwrite "$FW/configs/dnsmasq-homesteadlink.conf" /etc/dnsmasq.d/homesteadlink.conf 0100644
  # bluetooth main.conf: replace only if the stock one lacks ControllerMode.
  if debugfs -R "stat /etc/bluetooth/main.conf" "$ROOTPART_IMG" >/dev/null 2>&1; then
    debugfs -R "dump /etc/bluetooth/main.conf $WORK/main.conf.stock" "$ROOTPART_IMG" >/dev/null 2>&1 || true
    if [ -f "$WORK/main.conf.stock" ] && ! grep -q ControllerMode "$WORK/main.conf.stock"; then
      cat "$FW/configs/bluetooth-main.conf" >> "$WORK/main.conf.stock"
      echo "rm /etc/bluetooth/main.conf" >> "$CMDS"
      dwrite "$WORK/main.conf.stock" /etc/bluetooth/main.conf 0100644
    else
      log "stock /etc/bluetooth/main.conf already sets ControllerMode; left unchanged"
    fi
  else
    dwrite "$FW/configs/bluetooth-main.conf" /etc/bluetooth/main.conf 0100644
  fi
  # Enable units: manual symlinks (debugfs symlink syntax: link target).
  for u in hsl-bt-attach.service hsl-firstboot.service hsl-provisiond.service; do
    echo "symlink /etc/systemd/system/multi-user.target.wants/$u ../$u" >> "$CMDS"
  done
  debugfs -w -f "$CMDS" "$ROOTPART_IMG" > "$WORK/debugfs.log" 2>&1 || fail "debugfs injection failed (see $WORK/debugfs.log)"
  # Verify the payload actually landed.
  debugfs -R "stat /opt/homesteadlink/bin/hsl-provisiond" "$ROOTPART_IMG" 2>/dev/null | grep -q "Type: regular" || fail "payload verification failed: daemon not in image"
  debugfs -R "stat /etc/systemd/system/multi-user.target.wants/hsl-provisiond.service" "$ROOTPART_IMG" 2>/dev/null | grep -q "Type: symlink" || fail "payload verification failed: hsl-provisiond.service not enabled"
  log "injected payload verified via debugfs stat (daemon + enable symlinks)"
  debugfs -R "ls -l /opt/homesteadlink/bin" "$ROOTPART_IMG" 2>/dev/null | sed 's/^/[build-image] injected: /' || true
  # Write the partition back into the image.
  dd if="$ROOTPART_IMG" of="$IMG" bs=512 seek="$PSTART" conv=notrunc status=none
  log "partition written back into image (debugfs mode)"
fi

# --- 6. compress + report ---
OUT="$OUT_DIR/homesteadlink-orangepizero2w-$(date +%Y%m%d).img.xz"
log "compressing -> $OUT"
xz -T0 -kf -c "$IMG" > "$OUT"
log "sha256: $(sha256sum "$OUT" | awk '{print $1}')"
log "file: $OUT ($(stat -c %s "$OUT") bytes)"
