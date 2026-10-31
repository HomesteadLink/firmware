#!/bin/sh
# build-image.sh — HomeSteadyLink flashable image (§F1).
# Stock Armbian Ubuntu 24.04 (orangepizero2w) + §F1 package set +
# injected /opt/homesteadlink payload + enabled systemd units
# -> ONE .img.xz.
# Injection: loop-mount (root) preferred; without loop devices falls
# back to debugfs(8) writes into the extracted ext4 root partition.
# In debugfs mode the §F1 packages are installed by resolving arm64
# .debs (Ubuntu noble ports + the Tailscale repo), dpkg-extracting
# them into the rootfs and merging their dpkg status stanzas — the
# same fail-the-build dpkg assertions then run against the artifact.
# Env overrides: ARMBIAN_URL, ARMBIAN_IMG_XZ, GO, OUT_DIR, OUT_NAME,
# SKIP_DOWNLOAD=1.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FW=$(dirname "$HERE")
OUT_DIR=${OUT_DIR:-"$HERE/out"}
OUT_NAME=${OUT_NAME:-"homesteadlink-v1.1-orangepizero2w.img.xz"}
WORK=${WORK:-"$HERE/work"}
ARMBIAN_URL=${ARMBIAN_URL:-"https://archive.armbian.com/orangepizero2w/archive/Armbian_25.5.1_Orangepizero2w_noble_current_6.12.23.img.xz"}
PKGS="dnsmasq hostapd nftables"
ASSERT_PKGS="bluez wpasupplicant wireguard-tools dnsmasq hostapd nftables tailscale"
mkdir -p "$OUT_DIR" "$WORK"
log() { echo "[build-image] $*"; }
fail() { echo "[build-image] FAIL: $*" >&2; exit 1; }

# --- 1. daemon binary (arm64, static, no cgo) ---
BIN="$WORK/hsl-provisiond"
if [ -n "${GO:-}" ] || command -v go >/dev/null 2>&1; then
  GO=${GO:-go}
  log "building hsl-provisiond with $GO"
  ( cd "$FW/hsl-provisiond" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$GO" build -trimpath -ldflags "-s -w" -o "$BIN" . )
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
SHA_URL="${ARMBIAN_URL}.sha"
if curl -fsSL -o "$WORK/downloaded.sha" "$SHA_URL" 2>/dev/null; then
  EXPECTED=$(grep -oE '^[a-f0-9]{64}' "$WORK/downloaded.sha" | head -1 || true)
  if [ -n "${EXPECTED:-}" ]; then
    ACTUAL=$(sha256sum "$IMG_XZ" | awk '{print $1}')
    [ "$EXPECTED" = "$ACTUAL" ] || fail "checksum mismatch: expected $EXPECTED got $ACTUAL"
    log "checksum OK $ACTUAL"
  fi
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
  debugfs -R "ls -p /boot" "$ROOTPART_IMG" 2>/dev/null | awk -F/ '{print $6}' | grep -v '^$' > "$WORK/boot-list.txt" || true
  while IFS= read -r name; do
    case "$name" in
      config-*)
        [ -f "$ROOT/boot/$name" ] || debugfs -R "dump /boot/$name $ROOT/boot/$name" "$ROOTPART_IMG" >/dev/null 2>&1 || true
        ;;
    esac
  done < "$WORK/boot-list.txt"
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
  debugfs -R "dump /boot/armbianEnv.txt $WORK/armbianEnv.txt" "$ROOTPART_IMG" >/dev/null 2>&1 || true
  debugfs -R "dump /var/lib/dpkg/status $WORK/dpkg-status.stock" "$ROOTPART_IMG" >/dev/null 2>&1 || true
fi

# --- 3. §F3 kernel config assertions ---
KCFG=""
if [ "$MODE" = "loop" ]; then
  for cand in "$ROOT/boot/config-"* "$ROOT/usr/lib/modules/"*/config; do
    [ -f "$cand" ] && KCFG="$cand" && break
  done
else
  for cand in "$ROOT/boot/config-"*; do
    [ -f "$cand" ] && KCFG="$cand" && break
  done
fi
[ -n "$KCFG" ] || fail "no kernel config found in image - cannot run F3 assertions"
log "kernel config source: $KCFG"
MISSING=""
for sym in CONFIG_BT CONFIG_BT_HCIUART CONFIG_BT_HCIUART_H4 CONFIG_RFKILL \
           CONFIG_CFG80211 CONFIG_MAC80211 CONFIG_TUN \
           CONFIG_USB_GADGET CONFIG_USB_CONFIGFS CONFIG_USB_CONFIGFS_ECM \
           CONFIG_USB_CONFIGFS_NCM CONFIG_USB_CONFIGFS_ACM CONFIG_NF_NAT CONFIG_NF_TABLES; do
  if ! grep -qE "^${sym}=(y|m)" "$KCFG"; then MISSING="$MISSING $sym"; fi
done
# §F3 pins CONFIG_WIREGUARD=m exactly (F18).
grep -qE "^CONFIG_WIREGUARD=m" "$KCFG" || MISSING="$MISSING CONFIG_WIREGUARD(=m)"
[ -z "$MISSING" ] || fail "kernel config misses (F3):$MISSING"
log "kernel config assertions passed (F3, incl. CONFIG_WIREGUARD=m)"

# --- 4. §F2 DT overlay (F1): bt-uart.dtbo + merged-DT hard gate ---
if [ "$MODE" = "loop" ]; then
  DTB=$(ls "$ROOT/boot/dtb/"*/sun50i-h618-orangepi-zero2w.dtb "$ROOT/boot/dtb/sun50i-h618-orangepi-zero2w.dtb" 2>/dev/null | head -1 || true)
  [ -n "${DTB:-}" ] || DTB=$(find "$ROOT/boot" -name '*orangepi-zero2w*.dtb' 2>/dev/null | head -1 || true)
else
  DTB=$(ls "$ROOT/boot/"*orangepi-zero2w*.dtb 2>/dev/null | head -1 || true)
fi
[ -n "${DTB:-}" ] || fail "board DTB not found in shipped image"
DTBO="$WORK/bt-uart.dtbo"
if command -v dtc >/dev/null 2>&1; then
  dtc -@ -I dts -O dtb -o "$DTBO" "$FW/boards/orangepizero2w/bt-uart.dts" || fail "dtc failed on bt-uart.dts"
  log "bt-uart.dtbo compiled with dtc from boards/orangepizero2w/bt-uart.dts"
else
  python3 "$HERE/fdt_tools.py" make-overlay "$DTB" "$DTBO" || fail "fdt_tools make-overlay failed"
  log "bt-uart.dtbo generated with fdt_tools.py (no dtc on host; same nodes as bt-uart.dts)"
fi
# Hard gate: assertion runs on the MERGED tree (base + overlay) and
# FAILS THE BUILD otherwise. There is no waiver (§F2).
if python3 "$HERE/fdt_tools.py" assert "$DTB" "$DTBO" > "$WORK/dt-assertion.txt" 2>&1; then
  cat "$WORK/dt-assertion.txt" | sed 's/^/[build-image] /'
else
  cat "$WORK/dt-assertion.txt" | sed 's/^/[build-image] /' >&2
  fail "merged-DT assertion failed (F1/F2 hard gate) — see $WORK/dt-assertion.txt"
fi
# armbianEnv.txt: enable bt-uart via user_overlays (host-side edit;
# injected below in both modes).
ENV_FILE="$WORK/armbianEnv.new"
if [ "$MODE" = "loop" ]; then
  cp "$ROOT/boot/armbianEnv.txt" "$ENV_FILE" 2>/dev/null || : > "$ENV_FILE"
elif [ ! -s "$ENV_FILE" ]; then
  cp "$WORK/armbianEnv.txt" "$ENV_FILE" 2>/dev/null || : > "$ENV_FILE"
fi
if grep -q '^user_overlays=' "$ENV_FILE"; then
  grep -qE '^user_overlays=.*\bbt-uart\b' "$ENV_FILE" || sed -i 's/^user_overlays=.*/& bt-uart/' "$ENV_FILE"
else
  printf "user_overlays=bt-uart\n" >> "$ENV_FILE"
fi
log "armbianEnv user_overlays: $(grep '^user_overlays=' "$ENV_FILE")"

# --- 5. §F1 packages (F6) ---
STAGE="$WORK/pkg-stage"
rm -rf "$STAGE"; mkdir -p "$STAGE"
if [ "$MODE" = "loop" ]; then
  QEMU=$(command -v qemu-aarch64 || command -v qemu-aarch64-static || true)
  [ -n "$QEMU" ] || fail "loop mode package install needs qemu-aarch64"
  cp "$QEMU" "$ROOT/usr/bin/qemu-aarch64-static"
  cp /etc/resolv.conf "$ROOT/etc/resolv.conf" 2>/dev/null || true
  chroot "$ROOT" /usr/bin/qemu-aarch64-static /usr/bin/apt-get update || fail "chroot apt-get update failed"
  chroot "$ROOT" /usr/bin/qemu-aarch64-static /usr/bin/apt-get install -y --no-install-recommends $PKGS || fail "chroot apt install failed: $PKGS"
  curl -fsSL -o "$WORK/tailscale.deb" "$(python3 "$HERE/resolve_debs.py" --tailscale-url)" || fail "tailscale deb download failed"
  cp "$WORK/tailscale.deb" "$ROOT/tmp/tailscale.deb"
  chroot "$ROOT" /usr/bin/qemu-aarch64-static /usr/bin/dpkg -i /tmp/tailscale.deb || fail "tailscale dpkg -i failed"
  rm -f "$ROOT/usr/bin/qemu-aarch64-static" "$ROOT/tmp/tailscale.deb"
  for p in $ASSERT_PKGS; do
    chroot "$ROOT" /usr/bin/qemu-aarch64-static /usr/bin/dpkg -s "$p" >/dev/null 2>&1 || fail "dpkg -s $p failed in image (F6)"
  done
  log "package assertions passed via chroot dpkg -s: $ASSERT_PKGS"
else
  # debugfs mode: resolve + download arm64 debs, extract, stage.
  python3 "$HERE/resolve_debs.py" --stock-status "$WORK/dpkg-status.stock" \
      --out-dir "$WORK/debs" $PKGS tailscale > "$WORK/deb-plan.txt" || fail "deb resolution failed (see deb-plan)"
  cat "$WORK/deb-plan.txt" | sed 's/^/[build-image] deb: /'
  : > "$WORK/new-status-stanzas"
  for deb in "$WORK/debs/"*.deb; do
    [ -f "$deb" ] || fail "no debs downloaded"
    dpkg-deb -x "$deb" "$STAGE" || fail "dpkg-deb -x failed: $deb"
    # status stanza from the deb control, marked installed
    dpkg-deb -f "$deb" > "$WORK/stanza.txt"
    if ! grep -q "^Status:" "$WORK/stanza.txt"; then
      sed -i '1i Status: install ok installed' "$WORK/stanza.txt"
    fi
    cat "$WORK/stanza.txt" >> "$WORK/new-status-stanzas"
    echo "" >> "$WORK/new-status-stanzas"
  done
  rm -rf "$STAGE/var/lib/dpkg" "$STAGE/usr/share/doc"
  # merged dpkg status = stock + new stanzas (appended only for
  # packages the stock image lacks; resolve_debs.py excluded those)
  cp "$WORK/dpkg-status.stock" "$WORK/dpkg-status.new"
  printf "\n" >> "$WORK/dpkg-status.new"
  cat "$WORK/new-status-stanzas" >> "$WORK/dpkg-status.new"
fi

# --- 6. inject payload ---
# Files staged identically for both modes under $PAYSTAGE mirroring /.
PAY="$WORK/pay-stage"
rm -rf "$PAY"; mkdir -p "$PAY"
stage_file() { # src dest mode
  mkdir -p "$PAY$(dirname "$2")"
  cp "$1" "$PAY$2"
  chmod "$3" "$PAY$2"
}
stage_file "$BIN" /opt/homesteadlink/bin/hsl-provisiond 755
stage_file "$FW/systemd/hsl-firstboot.sh" /opt/homesteadlink/bin/hsl-firstboot.sh 755
stage_file "$FW/systemd/hsl-setup-code" /usr/local/bin/hsl-setup-code 755
stage_file "$FW/VERSION" /opt/homesteadlink/VERSION 644
for u in hsl-bt-attach.service hsl-firstboot.service hsl-provisiond.service; do
  stage_file "$FW/systemd/$u" "/etc/systemd/system/$u" 644
done
stage_file "$FW/systemd/bluetooth.service.d/override.conf" /etc/systemd/system/bluetooth.service.d/override.conf 644
stage_file "$FW/systemd/wpa_supplicant@wlan0.service.d/10-hsl.conf" "/etc/systemd/system/wpa_supplicant@wlan0.service.d/10-hsl.conf" 644
for c in "$FW/configs/"*; do
  [ -f "$c" ] && stage_file "$c" "/opt/homesteadlink/configs/$(basename "$c")" 644
done
stage_file "$FW/configs/nftables.conf" /etc/nftables.conf 644
stage_file "$FW/configs/dnsmasq-homesteadlink.conf" /etc/dnsmasq.d/homesteadlink.conf 644
stage_file "$FW/configs/hostapd-homesteadlink.conf" /etc/hostapd/hostapd.conf 644
stage_file "$FW/configs/bluetooth-main.conf" /etc/bluetooth/main.conf 644
stage_file "$FW/configs/networkd/20-usb0.network" /etc/systemd/network/20-usb0.network 644
stage_file "$FW/configs/networkd/30-wlan0.network" /etc/systemd/network/30-wlan0.network 644
stage_file "$DTBO" /boot/overlay-user/bt-uart.dtbo 644
stage_file "$ENV_FILE" /boot/armbianEnv.txt 644
mkdir -p "$PAY/etc/systemd/journald.conf.d"
printf "[Journal]\nStorage=persistent\n" > "$PAY/etc/systemd/journald.conf.d/hsl.conf"
chmod 644 "$PAY/etc/systemd/journald.conf.d/hsl.conf"
mkdir -p "$PAY/var/log/journal"
# package payload (debugfs mode) joins the same staging tree
if [ "$MODE" = "debugfs" ]; then
  ( cd "$STAGE" && tar cf - . ) | ( cd "$PAY" && tar xf - )
  stage_file "$WORK/dpkg-status.new" /var/lib/dpkg/status 644
fi

if [ "$MODE" = "loop" ]; then
  ( cd "$PAY" && tar cf - . ) | ( cd "$ROOT" && tar xf - )
  enable_unit() { mkdir -p "$ROOT/etc/systemd/system/multi-user.target.wants"; ln -sf "../$1" "$ROOT/etc/systemd/system/multi-user.target.wants/$1"; }
  enable_unit hsl-bt-attach.service; enable_unit hsl-firstboot.service; enable_unit hsl-provisiond.service
  enable_unit nftables.service; enable_unit dnsmasq.service; enable_unit tailscaled.service
  ln -sf "/lib/systemd/system/wpa_supplicant@.service" "$ROOT/etc/systemd/system/multi-user.target.wants/wpa_supplicant@wlan0.service"
  mkdir -p "$ROOT/etc/systemd/system/systemd-networkd.service.wants" 2>/dev/null || true
  ln -sf /dev/null "$ROOT/etc/systemd/system/ssh.service"
  ln -sf /dev/null "$ROOT/etc/systemd/system/sshd.service"
  ln -sf /dev/null "$ROOT/etc/systemd/system/NetworkManager.service"
  log "injected payload (loop mode)"
  sync; umount "$WORK/mnt"; losetup -d "$LOOP"; LOOP=""; trap - EXIT INT TERM
else
  CMDS="$WORK/debugfs.cmds"
  : > "$CMDS"
  # Directories first (parents before children), then files, then links.
  ( cd "$PAY" && find . -type d | sort ) | while IFS= read -r d; do
    [ "$d" = "." ] && continue
    echo "mkdir ${d#.}" >> "$CMDS"
  done
  ( cd "$PAY" && find . -type f ) | while IFS= read -r f; do
    rel="${f#.}"
    perm=$(stat -c %a "$PAY$rel")
    case "$perm" in *5|*7|*1|*3) typ=0100755;; *) typ=0100644;; esac
    # replaced files must be removed first (debugfs write won't overwrite)
    case "$rel" in
      /etc/bluetooth/main.conf|/boot/armbianEnv.txt|/var/lib/dpkg/status|/etc/nftables.conf)
        echo "rm $rel" >> "$CMDS" ;;
    esac
    echo "write $PAY$rel $rel" >> "$CMDS"
    echo "sif $rel mode $typ" >> "$CMDS"
  done
  ( cd "$PAY" && find . -type l ) | while IFS= read -r f; do
    rel="${f#.}"
    tgt=$(readlink "$PAY$rel")
    echo "symlink $rel $tgt" >> "$CMDS"
  done
  # enablement + masks as symlinks
  for u in hsl-bt-attach.service hsl-firstboot.service hsl-provisiond.service nftables.service dnsmasq.service tailscaled.service; do
    echo "symlink /etc/systemd/system/multi-user.target.wants/$u ../$u" >> "$CMDS"
  done
  echo "symlink /etc/systemd/system/multi-user.target.wants/wpa_supplicant@wlan0.service /lib/systemd/system/wpa_supplicant@.service" >> "$CMDS"
  echo "symlink /etc/systemd/system/ssh.service /dev/null" >> "$CMDS"
  echo "symlink /etc/systemd/system/sshd.service /dev/null" >> "$CMDS"
  echo "symlink /etc/systemd/system/NetworkManager.service /dev/null" >> "$CMDS"
  debugfs -w -f "$CMDS" "$ROOTPART_IMG" > "$WORK/debugfs.log" 2>&1 || fail "debugfs injection failed (see $WORK/debugfs.log)"
  # --- artifact assertions against the FINAL rootfs (F6) ---
  assert_stat() { debugfs -R "stat $1" "$ROOTPART_IMG" 2>/dev/null | grep -q "Type: regular" || fail "artifact assertion: $1 missing"; }
  assert_stat /opt/homesteadlink/bin/hsl-provisiond
  assert_stat /opt/homesteadlink/VERSION
  assert_stat /etc/nftables.conf
  assert_stat /etc/hostapd/hostapd.conf
  assert_stat /boot/overlay-user/bt-uart.dtbo
  assert_stat /usr/sbin/nft
  assert_stat /usr/sbin/dnsmasq
  assert_stat /usr/sbin/hostapd
  assert_stat /usr/bin/tailscale
  debugfs -R "stat /etc/systemd/system/multi-user.target.wants/hsl-provisiond.service" "$ROOTPART_IMG" 2>/dev/null | grep -q "Type: symlink" || fail "artifact assertion: hsl-provisiond.service not enabled"
  debugfs -R "dump /var/lib/dpkg/status $WORK/dpkg-status.final" "$ROOTPART_IMG" >/dev/null 2>&1 || fail "cannot dump final dpkg status"
  for p in $ASSERT_PKGS; do
    grep -q "^Package: $p\$" "$WORK/dpkg-status.final" || fail "dpkg assertion: package $p missing from final image status (F6)"
  done
  debugfs -R "ls -p /lib/firmware/uwe5622" "$ROOTPART_IMG" 2>/dev/null | grep -q "wcnmodem" || fail "firmware assertion: /lib/firmware/uwe5622 empty (F3)"
  debugfs -R "dump /etc/bluetooth/main.conf $WORK/main.conf.final" "$ROOTPART_IMG" >/dev/null 2>&1 || true
  grep -q "^ControllerMode" "$WORK/main.conf.final" || fail "bluetooth main.conf assertion: no uncommented ControllerMode (F14)"
  grep -q "^Name" "$WORK/main.conf.final" && fail "bluetooth main.conf assertion: Name= present (F14)"
  log "artifact assertions passed (dpkg set: $ASSERT_PKGS; binaries; firmware; bluetooth conf)"
  dd if="$ROOTPART_IMG" of="$IMG" bs=512 seek="$PSTART" conv=notrunc status=none
  log "partition written back into image (debugfs mode)"
fi

# --- 7. compress + report ---
OUT="$OUT_DIR/$OUT_NAME"
log "compressing -> $OUT"
xz -T0 -kf -c "$IMG" > "$OUT"
sha256sum "$OUT" | awk '{print $1"  '"$OUT_NAME"'"}' > "$OUT.sha256"
log "sha256: $(sha256sum "$OUT" | awk '{print $1}')"
log "file: $OUT ($(stat -c %s "$OUT") bytes)"
