# HomeSteadyLink firmware image

One flashable `.img.xz` = stock Armbian Ubuntu 24.04 (orangepizero2w) +
`/opt/homesteadlink/` payload (hsl-provisiond, systemd units, configs) +
enabled units. Built by `build-image.sh` (spec §F1/F2/F3 assertions run
inside the build and fail it on a miss).

## Build

```sh
sudo GO=$(command -v go) ./build-image.sh
# output: out/homesteadlink-orangepizero2w-<date>.img.xz (+ sha256 printed)
```

Env overrides: `ARMBIAN_URL`, `ARMBIAN_IMG_XZ`, `OUT_DIR`, `SKIP_DOWNLOAD=1`.

## Flash

balenaEtcher: select the `.img.xz`, select the SD card, Flash.

Or command line (replace `/dev/sdX` with the SD card device — check twice):

```sh
xzcat homesteadlink-orangepizero2w-<date>.img.xz | sudo dd of=/dev/sdX bs=4M status=progress conv=fsync
sync
```

Verify the download first if you received the image from elsewhere:

```sh
sha256sum homesteadlink-orangepizero2w-<date>.img.xz   # compare with the published sha256
```

## First boot

1. Insert the SD card, power the Orange Pi Zero 2W.
2. `hsl-firstboot` writes `/etc/homesteadlink/identity.json` (serial + setup code).
3. The device advertises as `HSL-<serial last4>` for 300 s (and permanently
   until Wi-Fi is configured). Provision from the app, or join the
   `HomesteadLink-<last4>` AP and open `http://192.168.64.1:8080`
   (usb0) or `http://192.168.65.1:8080` (AP mode). The AP passphrase
   is in `identity.json` (`ap_passphrase`): the §F1 domain-
   separated derivation — first 5 bytes of HMAC-SHA256(key =
   device-secret, message = serial + ":ap") mod 10^12, 12 digits.
   Independent of the setup code (different HMAC domain); the
   device-secret is its only secret input.
