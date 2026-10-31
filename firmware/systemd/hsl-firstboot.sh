#!/bin/sh
# hsl-firstboot (§F1, updated): identity follows the BOARD.
# serial: /proc/device-tree/serial-number; fallback = a random 128-bit
# value generated once and persisted. SD CID and hostname are NEVER
# serial sources. identity.json is re-derived every boot and
# regenerated when the board serial differs (cloned-card rule).
# secret: per-device 32 B at /etc/homesteadlink/device-secret (0600).
# The image contains NO secret — no batch/factory secret exists.
# setup code: full HMAC-SHA256(secret, serial) mod 10^6, %06d.
set -eu
DIR=/etc/homesteadlink
ID=$DIR/identity.json
SECRET_FILE=$DIR/device-secret
mkdir -p "$DIR"

# --- HSL-RESET factory reset (§F4 path b): flag file on the SD boot
# partition -> wipe bonds + committed/candidate wifi/vpn + state,
# keep identity.json + device-secret. ---
for flag in /boot/HSL-RESET /boot/firmware/HSL-RESET; do
  if [ -f "$flag" ]; then
    rm -f "$flag"
    rm -rf /var/lib/bluetooth/* 2>/dev/null || true
    rm -f "$DIR/wifi.conf" "$DIR/vpn.json" "$DIR/state.json" "$DIR/owner.json" "$DIR/owner.txt"
    rm -rf "$DIR/candidate" "$DIR/live"
    mkdir -p "$DIR/candidate" "$DIR/live"
    echo "hsl-firstboot: HSL-RESET flag processed — factory reset done" > /dev/console 2>/dev/null || true
  fi
done

# --- serial ---
SERIAL=$(tr -d '\0' < /proc/device-tree/serial-number 2>/dev/null | tr -d ' \t\r\n' || true)
if [ -z "${SERIAL:-}" ] && [ -s "$ID" ]; then
  # No board serial on this boot: keep the persisted identity serial.
  SERIAL=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' "$ID" | head -1)
fi
if [ -z "${SERIAL:-}" ]; then
  SERIAL=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
fi

# --- per-device secret (survives factory reset) ---
if [ ! -s "$SECRET_FILE" ]; then
  head -c 32 /dev/urandom > "$SECRET_FILE.tmp"
  chmod 600 "$SECRET_FILE.tmp"
  mv "$SECRET_FILE.tmp" "$SECRET_FILE"
fi
chmod 600 "$SECRET_FILE"
SECRET_HEX=$(od -An -tx1 "$SECRET_FILE" | tr -d ' \n')

# --- setup code: full-digest HMAC mod 10^6 (exact big-number mod via
# digit loop, not a 3-byte truncation) ---
DIGEST=$(printf '%s' "$SERIAL" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SECRET_HEX" -binary | od -An -tx1 | tr -d ' \n')
CODE=$(printf '%s' "$DIGEST" | awk '{
  n = 0
  for (i = 1; i <= length($0); i++) {
    c = substr($0, i, 1)
    d = index("0123456789abcdef", tolower(c)) - 1
    n = (n * 16 + d) % 1000000
  }
  printf "%06d", n
}')

# --- AP passphrase (R3-3 SECURITY): an INDEPENDENT high-entropy
# per-device secret from /dev/urandom, persisted in identity.json.
# It is NOT derived from the serial or the setup code (the old
# code+last4 derivation made it computable from public values). ---
AP_PASS=""
if [ -s "$ID" ]; then
  AP_PASS=$(sed -n 's/.*"ap_passphrase":"\([^"]*\)".*/\1/p' "$ID" | head -1)
fi
if [ -z "${AP_PASS:-}" ]; then
  AP_PASS=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
fi

# --- identity.json (write when changed: new board / first boot) ---
WANT="{\"serial\":\"$SERIAL\",\"setup_code\":\"$CODE\",\"ap_passphrase\":\"$AP_PASS\"}"
if [ ! -s "$ID" ] || [ "$(cat "$ID" 2>/dev/null)" != "$WANT" ]; then
  umask 077
  printf '%s\n' "$WANT" > "$ID.tmp"
  chmod 600 "$ID.tmp"
  mv "$ID.tmp" "$ID"
  sync
fi

LAST4=$(printf '%s' "$SERIAL" | tail -c 4)

# --- hostapd live config: SSID + AP passphrase substitution (§F1) ---
if [ -f /etc/hostapd/hostapd.conf ]; then
  sed -i "s/^ssid=.*/ssid=HomesteadLink-$LAST4/" /etc/hostapd/hostapd.conf
  sed -i "s/^wpa_passphrase=.*/wpa_passphrase=$AP_PASS/" /etc/hostapd/hostapd.conf
fi

# --- networkd wlan0 hostname: HSL-<last4> (§F4) ---
if [ -f /etc/systemd/network/30-wlan0.network ]; then
  sed -i "s/^Hostname=.*/Hostname=HSL-$LAST4/" /etc/systemd/network/30-wlan0.network
fi

# --- root password = setup code (§F4 hardening) ---
if command -v chpasswd >/dev/null 2>&1; then
  printf 'root:%s\n' "$CODE" | chpasswd || true
fi

# --- label data on the serial console (§F1 factory label flow) ---
for tty in /dev/ttyGS0 /dev/console; do
  if [ -w "$tty" ]; then
    printf 'HomeSteadyLink identity: serial=%s setup_code=%s ap_passphrase=%s\n' "$SERIAL" "$CODE" "$AP_PASS" > "$tty" 2>/dev/null || true
    break
  fi
done
