#!/bin/sh
# hsl-firstboot (§F1): identity follows the BOARD. Runs on EVERY boot
# (no early exit): the HSL-RESET flag check runs first, before
# identity derivation, even when identity.json already exists.
# serial: /proc/device-tree/serial-number; fallback = a random 128-bit
# value generated once and persisted in identity.json (authoritative
# once created; never re-derived, never regenerated — not even by
# HSL-RESET). SD CID and hostname are NEVER serial sources.
# secret: per-device 32 B at /etc/homesteadlink/device-secret (0600).
# The image contains NO secret — no batch/factory secret exists.
# Three domain-separated derivations, all keyed ONLY by the secret:
#   setup code       = HMAC(secret, serial)[0:3]        mod 10^6  (%06d)
#   console password = "HSL-" + HMAC(secret, serial+":console")[0:4] mod 10^8 (%08d)
#   AP passphrase    = HMAC(secret, serial+":ap")[0:5]   mod 10^12 (%012d)
set -eu
DIR=/etc/homesteadlink
ID=$DIR/identity.json
SECRET_FILE=$DIR/device-secret
mkdir -p "$DIR"
RESET_BOOT=0

# --- HSL-RESET factory reset (§F4 path b): flag file on the SD boot
# partition -> wipe bonds + committed/candidate wifi/vpn + state,
# keep identity.json + device-secret. ---
for flag in /boot/HSL-RESET /boot/firmware/HSL-RESET; do
  if [ -f "$flag" ]; then
    rm -f "$flag"
    RESET_BOOT=1
    rm -rf /var/lib/bluetooth/* 2>/dev/null || true
    rm -f "$DIR/wifi.conf" "$DIR/vpn.conf" "$DIR/state.json" "$DIR/owner.json"
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

# hmac_int <message> <hex-prefix-length> <modulus> -> integer mod m of
# the first N bytes of HMAC-SHA256(secret, message), via a running
# hex digit loop (exact for any prefix length).
hmac_int() {
  _digest=$(printf '%s' "$1" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$SECRET_HEX" -binary | od -An -tx1 | tr -d ' \n')
  _prefix=$(printf '%s' "$_digest" | cut -c1-"$2")
  printf '%s' "$_prefix" | awk -v mod="$3" '{
    n = 0
    for (i = 1; i <= length($0); i++) {
      d = index("0123456789abcdef", tolower(substr($0, i, 1))) - 1
      n = (n * 16 + d) % mod
    }
    printf "%d", n
  }'
}

CODE=$(printf '%06d' "$(hmac_int "$SERIAL" 6 1000000)")
CONSOLE="HSL-$(printf '%08d' "$(hmac_int "$SERIAL:console" 8 100000000)")"
AP_PASS=$(printf '%012d' "$(hmac_int "$SERIAL:ap" 10 1000000000000)")

# --- identity.json (write when changed: new board / first boot) ---
WANT="{\"serial\":\"$SERIAL\",\"setup_code\":\"$CODE\",\"console_password\":\"$CONSOLE\",\"ap_passphrase\":\"$AP_PASS\"}"
FRESH_ID=0
if [ ! -s "$ID" ] || [ "$(cat "$ID" 2>/dev/null)" != "$WANT" ]; then
  umask 077
  printf '%s\n' "$WANT" > "$ID.tmp"
  chmod 600 "$ID.tmp"
  mv "$ID.tmp" "$ID"
  sync
  FRESH_ID=1
fi

LAST4=$(printf '%s' "$SERIAL" | tail -c 4)

# --- hostapd live config: SSID + the :ap-derived passphrase (§F1) ---
if [ -f /etc/hostapd/hostapd.conf ]; then
  sed -i "s/^ssid=.*/ssid=HomesteadLink-$LAST4/" /etc/hostapd/hostapd.conf
  sed -i "s/^wpa_passphrase=.*/wpa_passphrase=$AP_PASS/" /etc/hostapd/hostapd.conf
fi

# --- networkd wlan0 hostname: HSL-<last4> (§F4) ---
if [ -f /etc/systemd/network/30-wlan0.network ]; then
  sed -i "s/^Hostname=.*/Hostname=HSL-$LAST4/" /etc/systemd/network/30-wlan0.network
fi

# --- root password = the CONSOLE password (§F1 — a separate secret
# from the setup code; the setup code is never the console credential) ---
if command -v chpasswd >/dev/null 2>&1; then
  printf 'root:%s\n' "$CONSOLE" | chpasswd || true
fi

# --- HSL-IDENTITY print rule (§F1/§F8 item 3): the FULL line (serial
# + setup code + console password + AP passphrase) prints ONLY at
# first boot (identity just written) and on an HSL-RESET boot; at
# later boots serial + the label pointer only — never the console
# password. ---
for tty in /dev/ttyGS0 /dev/console; do
  if [ -w "$tty" ]; then
    if [ "$RESET_BOOT" = 1 ] || [ "$FRESH_ID" = 1 ]; then
      printf 'HSL-IDENTITY serial=%s setup_code=%s console_password=%s ap_passphrase=%s\n' "$SERIAL" "$CODE" "$CONSOLE" "$AP_PASS" > "$tty" 2>/dev/null || true
    else
      printf 'HSL-IDENTITY serial=%s (full identity on the device label)\n' "$SERIAL" > "$tty" 2>/dev/null || true
    fi
    break
  fi
done
