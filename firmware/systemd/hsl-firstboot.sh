#!/bin/sh
# hsl-firstboot (§F1): generate /etc/homesteadlink/identity.json (0600) once.
# serial: /proc/cpuinfo Serial, fallback SD CID. setup code: 6-digit
# HMAC-SHA256(serial, factory secret) mod 1e6, zero-padded. The factory
# secret is baked per batch at image build time into
# /opt/homesteadlink/factory-secret (0600, root); if absent a per-device
# random secret is generated on first boot and kept (0600).
set -eu
DIR=/etc/homesteadlink
ID=$DIR/identity.json
[ -s "$ID" ] && exit 0
mkdir -p "$DIR"
SERIAL=$(awk -F': ' '/^Serial/{print $2}' /proc/cpuinfo | tr -d ' \t\r\n' || true)
if [ -z "${SERIAL:-}" ]; then
  for c in /sys/block/mmcblk0/device/cid /sys/block/mmcblk1/device/cid /sys/block/mmcblk2/device/cid; do
    [ -r "$c" ] && SERIAL=$(tr -d ' \t\r\n' < "$c") && break
  done
fi
[ -n "${SERIAL:-}" ] || SERIAL=$(hostname)
SECRET_FILE=/opt/homesteadlink/factory-secret
if [ ! -s "$SECRET_FILE" ]; then
  SECRET_FILE=$DIR/factory-secret
  if [ ! -s "$SECRET_FILE" ]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SECRET_FILE"
    chmod 600 "$SECRET_FILE"
  fi
fi
SECRET=$(cat "$SECRET_FILE")
# HMAC-SHA256 via openssl (present in the Armbian Ubuntu base).
HEX=$(printf '%s' "$SERIAL" | openssl dgst -sha256 -hmac "$SECRET" -binary | od -An -tu1 | awk '{n=$1*65536+$2*256+$3; printf "%06d", n % 1000000; exit}')
umask 077
printf '{"serial":"%s","setup_code":"%s"}\n' "$SERIAL" "$HEX" > "$ID.tmp"
chmod 600 "$ID.tmp"
mv "$ID.tmp" "$ID"
sync
