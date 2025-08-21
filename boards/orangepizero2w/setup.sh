#!/usr/bin/env bash
# Board-specific setup for Orange Pi Zero 2W (H616/H618)
# This file is sourced by the top-level setup script.
# It should define the following optional symbols/functions:
#   BOARD_NAME                  - short identifier
#   BOARD_OVERRIDES_GADGET      - when 'true', top-level won't run generic gadget setup
#   board_detect()              - return 0 if this script applies on current system
#   board_required_packages()   - echo space-separated package names to install
#   board_apply_dts_overlay()   - create/enable DT overlay to force USB peripheral mode
#   board_setup_gadget()        - set up USB gadget (configfs) + systemd units

set -euo pipefail

BOARD_NAME="orangepizero2w"
BOARD_OVERRIDES_GADGET=true

board_detect() {
  # Chroot-friendly detection (avoid relying solely on /proc)
  # 1) Explicit override via env
  case "${BOARD:-${FORCE_BOARD:-}}" in
    orangepizero2w|orangepi-zero2w|opi-zero2w|opi2w|opizero2w)
      return 0 ;;
  esac

  # 2) Armbian metadata
  if [ -f /etc/armbian-release ]; then
    if grep -qiE 'BOARD=orangepizero2|BOARD=orangepizero2w' /etc/armbian-release; then
      return 0
    fi
    if grep -qiE 'FAMILY=.*(h616|h618|sun50i-h616)' /etc/armbian-release; then
      return 0
    fi
  fi

  # 3) Boot DTBs
  if [ -f /boot/dtb/allwinner/sun50i-h616-orangepi-zero2.dtb ] || \
     [ -f /boot/dtb/allwinner/sun50i-h616-orangepi-zero2w.dtb ] || \
     [ -f /boot/dtb/allwinner/sun50i-h618-orangepi-zero2.dtb ] || \
     [ -f /boot/dtb/allwinner/sun50i-h618-orangepi-zero2w.dtb ] || \
     ls /boot/dtb/*zero2w*.dtb >/dev/null 2>&1 ; then
    return 0
  fi

  # 4) Runtime DT (when not in chroot)
  if [ -r /proc/device-tree/compatible ] && tr -d '\0' </proc/device-tree/compatible | grep -qiE 'sun50i-h616|sun50i-h618'; then
    return 0
  fi

  return 1
}

board_required_packages() {
  # dtc is needed to compile the overlay
  echo "device-tree-compiler"
}

board_apply_dts_overlay() {
  local BOOT="/boot"
  [ -d "$BOOT" ] || { echo "[BOARD:$BOARD_NAME] /boot not found"; return 0; }

  local ARMBIAN_ENV="$BOOT/armbianEnv.txt"
  local OPI_ENV="$BOOT/orangepiEnv.txt"
  local EXTLINUX_CONF="$BOOT/extlinux/extlinux.conf"

  local ODIR="$BOOT/overlay-user"
  mkdir -p "$ODIR"

  # Some builds require this symlink for overlays
  if [ -d "$BOOT/dtb/allwinner/overlay" ] && [ ! -e "$BOOT/dtb/overlay" ]; then
    (cd "$BOOT/dtb" && ln -sf ./allwinner/overlay overlay) || true
  fi

  local DTS="$ODIR/usb0-device.dts"
  local DTBO="$ODIR/usb0-device.dtbo"

  cat >"$DTS" <<'EOF'
/dts-v1/;
/plugin/;
/ {
  compatible = "allwinner,sun50i-h616", "allwinner,sun50i-h618";

  fragment@0 { target = <&usbotg>; __overlay__ { dr_mode = "peripheral"; status = "okay"; }; };
  fragment@1 { target = <&usbphy>;  __overlay__ { status = "okay"; }; };
  /* Prevent host controllers from grabbing PHY0 */
  fragment@2 { target = <&ehci0>;  __overlay__ { status = "disabled"; }; };
  fragment@3 { target = <&ohci0>;  __overlay__ { status = "disabled"; }; };
};
EOF

  echo "[BOARD:$BOARD_NAME] Compiling USB gadget overlay -> $DTBO"
  dtc -@ -I dts -O dtb -o "$DTBO" "$DTS"

  echo "[BOARD:$BOARD_NAME] Enabling overlay in boot config"
  if   [ -f "$ARMBIAN_ENV" ]; then
    touch "$ARMBIAN_ENV"
    if grep -q '^user_overlays=' "$ARMBIAN_ENV"; then
      grep -E '^user_overlays=.*\busb0-device\b' "$ARMBIAN_ENV" >/dev/null || \
        sed -i 's/^user_overlays=.*/& usb0-device/' "$ARMBIAN_ENV"
    else
      printf "\nuser_overlays=usb0-device\n" >> "$ARMBIAN_ENV"
    fi
    sed -i 's/user_overlays= \+/user_overlays=/; s/  \+/ /g' "$ARMBIAN_ENV"
  elif [ -f "$OPI_ENV" ]; then
    touch "$OPI_ENV"
    if grep -q '^overlays=' "$OPI_ENV"; then
      grep -E '^overlays=.*\busb0-device\b' "$OPI_ENV" >/dev/null || \
        sed -i 's/^overlays=.*/& usb0-device/' "$OPI_ENV"
    else
      printf "\noverlays=usb0-device\n" >> "$OPI_ENV"
    fi
    sed -i 's/overlays= \+/overlays=/; s/  \+/ /g' "$OPI_ENV"
  elif [ -f "$EXTLINUX_CONF" ]; then
    # Add FDTOOVERLAYS to default label
    local def
    def="$(awk '/^DEFAULT/{print $2}' "$EXTLINUX_CONF" || true)"
    if [ -n "$def" ]; then
      awk -v def="$def" -v path="$DTBO" '
        BEGIN{IN=0; added=0}
        /^LABEL[ \t]+/ {IN = ($2==def)}
        IN && /^ *FDT / {print; if (!added){print "  FDTOOVERLAYS " path; added=1}; next}
        {print}
        END{ if (!added && IN){ print "  FDTOOVERLAYS " path } }
      ' "$EXTLINUX_CONF" > "$EXTLINUX_CONF.new" && mv "$EXTLINUX_CONF.new" "$EXTLINUX_CONF"
    else
      grep -qF "FDTOOVERLAYS $DTBO" "$EXTLINUX_CONF" || printf "\nFDTOOVERLAYS %s\n" "$DTBO" >> "$EXTLINUX_CONF"
    fi
  else
    echo "[BOARD:$BOARD_NAME] WARNING: No known boot config found; overlay installed but not enabled"
  fi

  # Signal to caller that reboot is required to apply overlay
  REBOOT_REQUIRED=true
}

board_setup_gadget() {
  # Provide a composite gadget (ACM + ECM) using configfs and a oneshot service
  local GADGET_SH="/usr/local/sbin/setup-usb-gadget.sh"
  mkdir -p /usr/local/sbin
  cat >"$GADGET_SH" <<'EOSH'
#!/bin/sh
set -e
modprobe libcomposite 2>/dev/null || true
# Mount configfs if not already
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
G=/sys/kernel/config/usb_gadget/pi
[ -d "$G" ] || mkdir -p "$G"
cd "$G"
# Linux Foundation IDs (gadget)
echo 0x1d6b > idVendor
echo 0x0104 > idProduct
mkdir -p strings/0x409
echo "SteadyLink"      > strings/0x409/manufacturer
echo "USB 10/100/1000 LAN" > strings/0x409/product
echo "9810"         > strings/0x409/serialnumber
mkdir -p configs/c.1/strings/0x409
echo "ACM+ECM+RNDIS" > configs/c.1/strings/0x409/configuration
mkdir -p functions/acm.usb0
mkdir -p functions/ecm.usb0
mkdir -p functions/rndis.usb0
# Optional MACs can be provided via environment
[ -n "$DEV_MAC" ]  && echo "$DEV_MAC"  > functions/ecm.usb0/dev_addr || true
[ -n "$HOST_MAC" ] && echo "$HOST_MAC" > functions/ecm.usb0/host_addr || true
[ -n "$DEV_MAC" ]  && echo "$DEV_MAC"  > functions/rndis.usb0/dev_addr || true
[ -n "$HOST_MAC" ] && echo "$HOST_MAC" > functions/rndis.usb0/host_addr || true
ln -sf functions/acm.usb0 configs/c.1/
ln -sf functions/ecm.usb0 configs/c.1/
ln -sf functions/rndis.usb0 configs/c.1/
# Enable Microsoft OS descriptors for better Windows RNDIS support
mkdir -p os_desc
echo 1 > os_desc/use
echo MSFT100 > os_desc/qw_sign
echo 0x01 > os_desc/b_vendor_code
ln -sf configs/c.1 os_desc
UDC=$(ls /sys/class/udc 2>/dev/null | head -n1 || true)
[ -n "$UDC" ] && echo "$UDC" > UDC || true
# Bring up usb0 with STATIC_IP if present
if [ -n "$STATIC_IP" ] && ip link show usb0 >/dev/null 2>&1; then
  ip addr add "$STATIC_IP" dev usb0 2>/dev/null || true
  ip link set usb0 up || true
fi
EOSH
  chmod +x "$GADGET_SH"

  # systemd unit to run gadget setup early
  mkdir -p /etc/systemd/system
  cat >/etc/systemd/system/usb-gadget.service <<'EOF'
[Unit]
Description=USB Gadget (ACM + ECM + RNDIS) bringup
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/setup-usb-gadget.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  ln -sf ../usb-gadget.service /etc/systemd/system/multi-user.target.wants/usb-gadget.service

  # Enable login on USB serial (ttyGS0) when available
  local GETTY_TEMPLATE=""
  for p in /lib/systemd/system/serial-getty@.service /usr/lib/systemd/system/serial-getty@.service; do
    [ -f "$p" ] && GETTY_TEMPLATE="$p" && break
  done
  if [ -n "$GETTY_TEMPLATE" ]; then
    mkdir -p /etc/systemd/system/getty.target.wants
    ln -sf "$GETTY_TEMPLATE" /etc/systemd/system/getty.target.wants/serial-getty@ttyGS0.service
  fi
}
