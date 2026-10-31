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
