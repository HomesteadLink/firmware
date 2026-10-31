# HomeSteadyLink — GATT Contract v1

Single source of truth for firmware (`hsl-provisiond`), Android, and iOS.
Refs: `HomesteadLink/firmware#6` (firmware). If code and this
document disagree, this document wins until it is amended in this repo.

All payloads are UTF-8 JSON, no trailing NUL, no BOM. Length limits below
are byte lengths of the UTF-8 encoding. Unknown JSON fields are ignored.
Senders must not emit fields with types other than those specified.

## 1. Transport and security

- UUIDs are full 128-bit values, listed explicitly in §2–§3. All seven
  share the base `-1c2d-4e5f-8a9b-0c1d2e3f4a5b`; the leading group runs
  `7f3a0000` (service) through `7f3a0006` (Control). There is no
  16/32-bit short-form expansion.
- MTU: client requests MTU 185; ATT payload is therefore 182 bytes
  (185 − 3). No single ATT read, write, or notification value exceeds
  182 bytes. Larger payloads use the chunking rules in §4.
- Security: LE Secure Connections required, bonding required.
  Unencrypted links carry only `DeviceInfo` (§3).
- Pairing: Passkey Entry. Device IO capability: `KeyboardOnly`.
  The passkey is a 6-digit decimal code, unique per device (the device's
  setup code; not a fixed/default code). Pairing fails close the link.
- Authorization: a write to any encrypted characteristic from an
  unbonded / unencrypted peer fails with ATT error `0x05`
  (Insufficient Authentication). The same applies to reading an
  encrypted characteristic on an unencrypted link. No config is
  applied, in whole or in part, on a failed write.
- Owner: the first bonded peer is the only owner. Owner identity is
  the BlueZ bond record: the device stores the owner's identity
  address + IRK (from `/var/lib/bluetooth`); BlueZ resolves the
  owner's rotating RPA via the IRK, so the owner is recognized across
  address rotation — never keyed on the BD_ADDR of the moment or on
  an OS peripheral UUID. Bond attempts by any other peer are rejected
  until the owner bond is removed (`Control: unbond`, §3) or the
  device is factory-reset. Only the owner may write `WifiConfig`,
  `VpnConfig`, or `Control`, or read the encrypted characteristics;
  the owner check fails closed when the peer cannot be identified.
- Pairing lockout: failed passkey attempts are counted (persisted).
  5 failures inside one window close the window immediately and lock
  bonding for 15 min; each further lockout doubles it (30 min, cap
  60 min). A successful bond or a factory reset clears the counter.
- Provisioning window: provisioning (advertising the service in §2,
  accepting new connections and new bonds) is open for 300 s after
  boot. While no Wi-Fi config is stored, the window is permanently
  open. After the window closes (Wi-Fi config present, 300 s elapsed):
  advertising stops, new connections/bonds are refused, an already
  connected owner session continues until disconnect, and
  `Control: close_window` ends the window immediately at any time.
  A reboot re-opens the window for 300 s. The window also closes
  automatically when setup reaches `online`/`online_no_vpn`. On
  close, all three enforcements apply: advertising stops; the
  adapter is set non-discoverable AND non-pairable; non-owner
  centrals are disconnected and new connections/pairing from
  non-owners are rejected (an already-connected owner continues).

## 2. Service

| Name | UUID |
|---|---|
| HomeSteadyLink Provisioning | `7f3a0000-1c2d-4e5f-8a9b-0c1d2e3f4a5b` |

The device advertises this service UUID; clients scan filtered by it.

## 3. Characteristics

| Name | Leading group | Full UUID base | Properties | Security |
|---|---|---|---|---|
| DeviceInfo | `7f3a0001` | `-1c2d-4e5f-8a9b-0c1d2e3f4a5b` | Read | None (plaintext) |
| WifiScan | `7f3a0002` | `-1c2d-4e5f-8a9b-0c1d2e3f4a5b` | Read, Notify | Encrypted |
| WifiConfig | `7f3a0003` | `-1c2d-4e5f-8a9b-0c1d2e3f4a5b` | Write (with response) | Encrypted + bonded |
| VpnConfig | `7f3a0004` | `-1c2d-4e5f-8a9b-0c1d2e3f4a5b` | Write (with response) | Encrypted + bonded |
| Status | `7f3a0005` | `-1c2d-4e5f-8a9b-0c1d2e3f4a5b` | Read, Notify | Encrypted |
| Control | `7f3a0006` | `-1c2d-4e5f-8a9b-0c1d2e3f4a5b` | Write (with response) | Encrypted + bonded |

Full UUID = leading group + base, e.g. DeviceInfo is
`7f3a0001-1c2d-4e5f-8a9b-0c1d2e3f4a5b`. Notify is enabled via the
standard CCCD (0x2902) on `WifiScan` and `Status`.

### DeviceInfo — JSON, ≤128 B

```json
{"model":"string","serial":"string","fw":"string"}
```

| Field | Type | Meaning |
|---|---|---|
| `model` | string | Hardware model identifier. |
| `serial` | string | Per-device serial number. |
| `fw` | string | Firmware version, e.g. `"1.0.0"`. This is the only version field in the contract: there is no separate GATT-contract version characteristic. Clients key compatibility behaviour off `fw`. |

Readable before bonding, so a client can identify the device and its
firmware before pairing.

### WifiScan — one access point per value, JSON, ≤182 B each

```json
{"idx":0,"total":3,"ssid":"string","bssid":"aa:bb:cc:dd:ee:ff","rssi":-60,"band":"5","channel":36,"security":"wpa2","secure":true}
```

| Field | Type | Meaning |
|---|---|---|
| `idx` | integer ≥ 0 | Index of this result, 0-based. |
| `total` | integer ≥ 0 | Total number of results in this scan. |
| `ssid` | string | Network name, ≤32 UTF-8 bytes. |
| `bssid` | string | AP MAC address. |
| `rssi` | integer | Signal strength in dBm (negative). |
| `band` | string | `"2.4"` or `"5"` (GHz). |
| `channel` | integer | Wi-Fi channel number. |
| `security` | string enum | `wpa2` \| `wpa3` \| `trans` (WPA2/3 transition) \| `eap` \| `open`. |
| `secure` | boolean | `true` if the AP requires a passphrase. |

Scan is refused with `error=busy` (Status) while a join/VPN
transaction runs; it is allowed in idle and online. App-side rule:
results are deduplicated by SSID (strongest RSSI shown); the device
joins the strongest BSSID unless the user picks one, which sets
`WifiConfig.bssid`.

Behaviour and reassembly: §4.1. Reading `WifiScan` triggers a scan.

### WifiConfig — Write, JSON, ≤512 B

```json
{"ssid":"string","psk":"string","country":"US","hidden":false,"bssid":"aa:bb:cc:dd:ee:ff"}
```

| Field | Type | Meaning |
|---|---|---|
| `ssid` | string, 1–32 UTF-8 bytes | Network to join. Required. |
| `psk` | string | Passphrase: 8–63 ASCII chars, or 64 hex chars (raw PSK). `""` for an open network (only valid when the scan reported `secure:false`). Required. |
| `country` | string | ISO 3166-1 alpha-2, uppercase, e.g. `"US"`. Regulatory domain. Required. |
| `hidden` | boolean | `true` if the SSID is not broadcast. |
| `bssid` | string, optional | Pin the join to this AP (from `WifiScan`). |
| `security` | string, optional | Scan-reported class (`wpa2`/`wpa3`/`trans`/`eap`/`open`); an `eap` target is rejected with `error=unsupported_eap`. |

Security matrix: WPA2-PSK → `key_mgmt=WPA-PSK`; WPA2/3 transition →
`WPA-PSK SAE` with pmf=1 (an AP that rejects SAE falls back to
WPA-PSK on retry); WPA3-SAE only → `SAE` with pmf=2; open → `NONE`.
A join rejected on regulatory grounds reports
`error=regdom_mismatch`, never `auth_failed`. The whole apply
transaction has one 90 s budget.

Field limits keep a valid `WifiConfig` under 182 B, so it is always a
single ATT write; the 512 B figure is the validation ceiling — a longer
value is rejected, never truncated. A successful write stores the
config and starts the join sequence (watch `Status`).

### VpnConfig — Write, JSON, ≤4096 B total

Exactly one of two shapes:

```json
{"type":"wireguard","conf":"string"}
{"type":"tailscale","authkey":"string","exit_node":"string"}
```

| Field | Type | Meaning |
|---|---|---|
| `type` | string enum | `"wireguard"` or `"tailscale"`. Required. |
| `conf` | string | Complete WireGuard config file text (INI). Required for `wireguard`, absent otherwise. |
| `authkey` | string | Tailscale auth key. Required for `tailscale`, absent otherwise. |
| `exit_node` | string, optional | Tailscale exit node (tailnet name or IP). Tailscale shape only. |

WireGuard configs are validated before storing: `[Interface]` with
PrivateKey + Address and ≥1 `[Peer]` whose AllowedIPs includes
`0.0.0.0/0` (full tunnel); anything else is rejected with
`error=vpn_not_full_tunnel`. A stored config takes effect only
through the validated raise: `online` requires a WireGuard handshake
within 20 s + the default route via wg-hsl, or Tailscale
BackendState=Running + netcheck UDP; failure is state `vpn_failed`.
If Tailscale reports the key expired, `error=authkey_expired`.

Chunking and reassembly: §4.2. A successful (complete, valid) write
stores the config; it takes effect on `Control: vpn_start` or, if
Wi-Fi comes online with a VPN config stored, automatically as part of
the join sequence.

### Status — Read + Notify, JSON, ≤128 B

```json
{"state":"idle","error":null,"ssid":null,"ip4":null,"vpn":false}
```

| Field | Type | Meaning |
|---|---|---|
| `state` | string enum | See states below. |
| `error` | string \| null | `null`, or one of the error codes below. |
| `ssid` | string \| null | Joined (or joining) network; `null` if none. |
| `ip4` | string \| null | Dotted-quad IPv4 address on the WLAN interface; `null` until DHCP completes. |
| `vpn` | boolean | `true` only while the VPN tunnel is up. |

States (`state`, exact strings):

`idle`, `scanning`, `wifi_joining`, `wifi_auth_failed`, `dhcp`,
`internet_check`, `vpn_starting`, `online`, `online_no_vpn`,
`vpn_failed`, `captive_portal`, `factory_reset`

(`bt_dead` is an ERROR code only, never a state.)

- `online` is the success terminal state when a VPN is up: Wi-Fi
  joined, internet check passed, and the VPN raise validated
  (handshake/route or BackendState/netcheck). A VpnConfig write
  alone NEVER sets `online`.
- `online_no_vpn` is the terminal state when the user skipped VPN:
  Wi-Fi + internet up; the kill switch still drops forwarded
  traffic (no VPN = no client egress, by design).
- `vpn_failed` = Wi-Fi is up but the VPN raise/validation failed;
  committed Wi-Fi is kept.
- `wifi_auth_failed` and `captive_portal` are failure states:
  `wifi_auth_failed` = AP rejected the passphrase;
  `captive_portal` = internet check found a portal (recover with
  `Control: portal_pass` after the user signs in). A failed
  Bluetooth stack/radio is reported as `error:"bt_dead"` on the
  current state — `bt_dead` is never a state value.
- `factory_reset` is emitted once, just before the device erases
  config and bond and reboots.

Error codes (`error`, exact strings, or `null` when there is no error):

`auth_failed`, `timeout`, `bt_dead`, `captive_portal`, `dhcp_failed`,
`vpn_failed`, `vpn_not_full_tunnel`, `vpn_config_invalid`,
`unsupported_eap`, `regdom_mismatch`, `authkey_expired`, `busy`

Firmware sets `error` together with the state that reports the
failure (e.g. `state:"wifi_auth_failed", error:"auth_failed"`;
`state:"dhcp", error:"dhcp_failed"`; `state:"online", error:null` on
success) and notifies subscribers on every state or error change.
Reading `Status` returns the current value without changing it.

### Control — Write, JSON

```json
{"cmd":"reboot"}
```

| Field | Type | Meaning |
|---|---|---|
| `cmd` | string enum | One command per write, exact strings below. |

| Command | Effect |
|---|---|
| `reboot` | Reboot the device. Re-opens the provisioning window (300 s). |
| `factory_reset` | Emit `Status: factory_reset`, erase Wi-Fi config, VPN config, and the owner bond, then reboot. |
| `close_window` | End the provisioning window now (same end state as the 300 s timeout). |
| `vpn_stop` | Stop the VPN tunnel. Wi-Fi stays joined. |
| `vpn_start` | Start the VPN from the stored `VpnConfig`. No-op success if already up. |
| `unbond` | Delete the owner bond, then disconnect. Device returns to the no-owner state; the next bonded peer becomes owner. |
| `portal_pass` | Two distinct operations: with no active grant it only OPENS the 10-minute portal exception (destination-scoped, §F4) — granting never re-runs the check as a side effect. While a grant is active, `portal_pass` is the explicit RECHECK trigger: firmware re-runs the internet check (`internet_check` → `online` / `captive_portal`) without extending the grant. |
| `diagnostics` | Build `/etc/homesteadlink/diag.tar.gz` (journal last 24 h for hsl tags, state.json, `nft list ruleset`, `tailscale status`); the app downloads it from the config page `/diagnostics` endpoint with the setup-code token. |

Any other `cmd` value is rejected and changes nothing.

## 4. Chunking and reassembly

### 4.1 WifiScan (device → client)

1. A Read of `WifiScan` triggers a fresh scan (`Status: scanning`),
   discarding any previous result set. Clients must subscribe to
   notifications (CCCD) before reading, or results are missed.
2. Each result is sent as one notification value (and is the value a
   subsequent Read returns, for the most recent result): one complete
   JSON object, ≤182 B, one AP per object, in `idx` order starting
   at 0.
3. The set is complete when the client has received the object with
   `idx = total − 1`. Objects may only be reassembled within one scan:
   a new Read, or a change in `total`, invalidates earlier objects.
   Duplicate `idx` values: the later object replaces the earlier one.
4. Empty scan: the device sends exactly one object
   `{"idx":0,"total":0,"ssid":"","bssid":"","rssi":0,"band":"","channel":0,"security":"open","secure":false}` and returns
   `Status` to `idle`. `total:0` is the terminal marker; the other
   fields carry no meaning in that object.
5. Hidden APs (no broadcast SSID) are not reported in scan results.

### 4.2 VpnConfig (client → device)

Applies only when the JSON payload is >182 B; a payload ≤182 B is
sent as a single unchunked write with no header (see rule 2).

1. The client splits the UTF-8 JSON payload into chunks. Every chunk
   is one Write-with-response value of ≤182 B: byte 0 is the sequence
   header `[seq]`, the remaining ≤181 B are the next payload bytes.
   `seq` is 1 byte, 0-based, incrementing by 1 per chunk.
2. Discrimination: a first write whose first byte is `{` (0x7B) is an
   unchunked complete payload. In chunked mode the first write has
   `seq = 0`. (A JSON payload never begins with byte 0x00, so the two
   modes are unambiguous.)
3. The client sends chunks strictly in order, waiting for each write
   response before sending the next. Firmware appends payload bytes in
   `seq` order to a reassembly buffer.
4. End of payload: a chunk carrying <181 payload bytes is the final
   chunk. If the final chunk carries exactly 181 payload bytes, the
   client sends one extra terminating chunk: header only
   (`seq` = next value, zero payload bytes, value length 1).
5. On the final chunk, firmware parses the reassembled buffer as
   JSON and validates it against §3 (`VpnConfig`, ≤4096 B total).
   Valid → config stored. Invalid, oversized, or unparseable →
   nothing is stored and the result is synchronous: `Status`
   notifies `error=vpn_config_invalid` (or `vpn_not_full_tunnel`)
   at once, not deferred to the next start.
6. Reset conditions — buffer discarded, no config applied: a chunk
   with `seq = 0` (starts a new transfer), an out-of-order `seq`
   (≠ previous `seq` + 1), a disconnect, or a new unchunked write.
   There is no resume: the client restarts from `seq = 0`.

`WifiConfig` is never chunked (§3). `DeviceInfo` and `Status` values
always fit in one ATT payload by construction (≤128 B).
