#!/bin/sh
set -e
modprobe libcomposite 2>/dev/null || true
modprobe usb_f_fs 2>/dev/null || true
# Mount configfs if not already
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
# Mount FunctionFS for the WebUSB vendor interface (hsl-provisiond
# writes descriptors to /dev/ffs-usb/ep0, then binds the UDC).
mkdir -p /dev/ffs-usb
mountpoint -q /dev/ffs-usb || mount -t functionfs usb /dev/ffs-usb
G=/sys/kernel/config/usb_gadget/pi
[ -d "$G" ] || mkdir -p "$G"
cd "$G"
# Linux Foundation IDs (gadget)
echo 0x1d6b > idVendor
echo 0x0104 > idProduct
mkdir -p strings/0x409
echo "SteadyLink"      > strings/0x409/manufacturer
echo "HomeSteadyLink" > strings/0x409/product
echo "9810"         > strings/0x409/serialnumber
mkdir -p configs/c.1/strings/0x409
echo "ACM+ECM+RNDIS+FFS" > configs/c.1/strings/0x409/configuration
mkdir -p functions/acm.usb0
mkdir -p functions/ecm.usb0
mkdir -p functions/rndis.usb0
mkdir -p functions/ffs.usb0
# Optional MACs can be provided via environment
[ -n "$DEV_MAC" ]  && echo "$DEV_MAC"  > functions/ecm.usb0/dev_addr || true
[ -n "$HOST_MAC" ] && echo "$HOST_MAC" > functions/ecm.usb0/host_addr || true
[ -n "$DEV_MAC" ]  && echo "$DEV_MAC"  > functions/rndis.usb0/dev_addr || true
[ -n "$HOST_MAC" ] && echo "$HOST_MAC" > functions/rndis.usb0/host_addr || true
ln -sf functions/acm.usb0 configs/c.1/
ln -sf functions/ecm.usb0 configs/c.1/
ln -sf functions/rndis.usb0 configs/c.1/
ln -sf functions/ffs.usb0 configs/c.1/
# Enable Microsoft OS descriptors for better Windows RNDIS support
mkdir -p os_desc
echo 1 > os_desc/use
echo MSFT100 > os_desc/qw_sign
echo 0x01 > os_desc/b_vendor_code
# WinUSB binding for the vendor (FunctionFS) interface: Windows
# matches the compatible ID and loads WinUSB with no manual driver.
mkdir -p os_desc/interface.ffs.usb0
echo "WINUSB" > os_desc/interface.ffs.usb0/compatible_id
ln -sf configs/c.1 os_desc
# NOTE: the UDC bind is owned by hsl-provisiond (USB transport). It
# writes the FunctionFS descriptors to /dev/ffs-usb/ep0 first, then
# binds the UDC — descriptors must exist before the host enumerates
# the interface. Binding here would enumerate ffs.usb0 with no
# descriptors. usb0's address comes from systemd-networkd
# (20-usb0.network, 192.168.64.1/24) once the gadget binds.
