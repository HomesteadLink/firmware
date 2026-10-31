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
- MTU: the client requests MTU 185 where the platform allows it
  (Android); iOS negotiates via CoreBluetooth. Both apps READ the
  negotiated MTU. ATT payload = min(182, negotiated MTU − 3). No
  single ATT read, write or notification value — chunked or not —
  exceeds the payload (§4.3). If the negotiated MTU is < 23, the
  payload is < 20 B and provisioning is impossible: the app aborts
  with the error 'BLE MTU too small' and the device accepts no
  config on that link.
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
- Owner: the first bonded peer is the only owner. The device stores
  exactly one bond, enforced in hsl-provisiond: before the pairing
  agent answers a passkey/confirmation request, provisiond counts
  the bond records in the BlueZ bond store
  (`/var/lib/bluetooth/<adapter>/`, one device directory per bond);
  a request from a device that is not the existing bond is rejected
  (agent returns Rejected) and the requester is disconnected — no
  second bond is created. At startup provisiond removes all but the
  oldest bond record if more than one exists. Bond attempts by any
  other peer are rejected until the owner bond is removed
  (`Control: unbond`, §3) or the device is factory-reset. Only the
  owner may write `WifiConfig`, `VpnConfig` or `Control`, or read
  the encrypted characteristics. Owner identity is the bond record
  (incl. IRK resolution of rotating addresses), never the BD_ADDR of
  the moment.
- Pairing lockout: failed passkey attempts are counted in
  `state.json` (persisted, fsync). The failure window is 60 min of
  POWERED time (monotonic clock; wall clock is never used — an
  unconfigured device has no RTC/NTP). The window opens at the first
  failure; remaining durations are counted down while powered,
  persisted on every failure and at least every 10 s, and resumed at
  startup; powered-off time does not count down. 5 failures inside
  one window → the window closes immediately, the failure count
  resets, and bonding locks out for 15 min of powered time, doubled
  per lockout (30 min, cap 60 min). After a lockout expires, 5 fresh
  failures are required for the next lockout, but the lockout count
  PERSISTS (so the next lockout is longer); it resets to 0 only on a
  successful bond or a factory reset. Applies in the 300 s boot
  window and in the permanent unconfigured window.
- Provisioning window: the window (advertising the §2 service as
  discoverable, accepting NEW bonds/pairing) is open for 300 s after
  boot and permanently while no Wi-Fi config is stored. The window
  gates new bonds only. After it closes: advertising continues as
  connectable, non-discoverable, without the service UUID; the
  adapter is non-pairable; the bonded owner may connect at ANY time
  (admission is by the BlueZ bond record, incl. IRK resolution of
  rotating addresses — clients reconnect via the OS bond record, not
  via scan); any non-owner connection is disconnected immediately
  and new pairing requests are refused. `Control: close_window`
  ends the window immediately at any time. A reboot re-opens the
  window for 300 s. The window also closes automatically when setup
  reaches `online`/`online_no_vpn`.

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
| `serial` | string | Per-device serial number (always in full, never truncated). |
| `fw` | string | Firmware version — the image version string in `/opt/homesteadlink/VERSION`. This is the only version field in the contract: there is no separate GATT-contract version characteristic. Clients key compatibility behaviour off `fw`. |

Readable before bonding, so a client can identify the device and its
firmware before pairing.

### WifiScan — one access point per value, JSON, ≤ the current ATT payload (§4.3) each

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
| `secure` | boolean | `true` unless `security` is `open`. |

Scan is refused with `error=busy` (Status) while a join/VPN
transaction runs; it is allowed in idle and online. App-side rule:
results are deduplicated by SSID (strongest RSSI shown); the device
joins the strongest BSSID unless the user picks one, which sets
`WifiConfig.bssid`.

Behaviour and reassembly: §4.1. Reading `WifiScan` triggers a scan;
subscribing to notifications does NOT (notifications only deliver
results).

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
| `security` | string, optional | Scan-reported class (`wpa2`/`wpa3`/`trans`/`eap`/`open`); an `eap` target is rejected with `error=unsupported_eap`. If absent (typed SSID), the device runs a targeted scan at transaction start and applies the same matrix; a typed SSID the targeted scan does not find is rejected with `error=wifi_config_invalid` (a `hidden:true` SSID proceeds with `scan_ssid=1`). |

Security matrix: WPA2-PSK → `key_mgmt=WPA-PSK`; WPA2/3 transition →
`WPA-PSK SAE` with pmf=1 (an AP that rejects SAE falls back to
WPA-PSK on retry); WPA3-SAE only → `SAE` with pmf=2; open → `NONE`.
A join rejected on regulatory grounds (target channel outside the
`iw reg get` permitted set for `country`) reports
`error=regdom_mismatch`, never `auth_failed`. The whole apply
transaction has one 90 s budget (portal-pause time excluded).

Field limits keep a valid WifiConfig at ~176 B worst case (with
`bssid`). WifiConfig is sent as ONE ATT write when its JSON fits the
current payload (§4.3); when it does not fit (a small-MTU link), it
uses the §4.2 chunking exactly like VpnConfig. The 512 B figure is
the validation ceiling — a longer value is rejected, never
truncated. A successful write stores the config and starts the join
sequence (watch `Status`).

### VpnConfig — Write, JSON, ≤4096 B total

Exactly one of two shapes:

```json
{"type":"wireguard","conf":"string"}
{"type":"tailscale","authkey":"string","exit_node":"string (optional)"}
```

`exit_node` = tailnet name or IP of the exit node; absent = no exit
node.

WireGuard configs are validated before storing: `[Interface]` with
PrivateKey + Address and ≥1 `[Peer]` whose AllowedIPs includes
`0.0.0.0/0` (full tunnel); anything else is rejected with
`error=vpn_not_full_tunnel`. A stored config takes effect only
through the validated raise: `online` requires a WireGuard handshake
within 30 s + the default route via wg-hsl, or Tailscale
BackendState=Running + netcheck UDP (plus a successful
`tailscale ping` to `exit_node` when one is set); failure is state
`vpn_failed`. If Tailscale reports the key expired,
`error=authkey_expired`.

Chunking and reassembly: §4.2. A successful (complete, valid) write
stores the config; it takes effect on `Control: vpn_start` or, if
Wi-Fi comes online with a VPN config stored, automatically as part
of the join sequence. A VpnConfig write alone NEVER sets `online`
(or any terminal state).

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

States (exact strings): idle, scanning, wifi_joining,
wifi_auth_failed, dhcp, internet_check, vpn_starting, online,
online_no_vpn, vpn_failed, captive_portal, factory_reset.

Terminal success states: `online` (Wi-Fi joined, internet check
passed, VPN up) and `online_no_vpn` (the user skipped VPN: Wi-Fi +
internet up, and the kill switch still drops all forwarded client
traffic). `vpn_failed` = Wi-Fi + internet up, the VPN raise or its
commit check failed. Failure states: wifi_auth_failed (AP rejected
the passphrase), captive_portal (recover via Control portal_pass /
portal_recheck). `bt_dead` is NOT a state — it is an error code
only; when Bluetooth fails, `state` keeps the current operational
state and `error` carries bt_dead. factory_reset is emitted once,
just before the device erases config and bond and reboots.

Error codes (`error`, exact strings, or `null` when there is no error):

`auth_failed`, `timeout`, `bt_dead`, `captive_portal`, `dhcp_failed`,
`vpn_failed`, `vpn_not_full_tunnel`, `vpn_config_invalid`,
`unsupported_eap`, `regdom_mismatch`, `authkey_expired`,
`wifi_config_invalid`, `busy`, `internet_unreachable`

Firmware sets `error` together with the state that reports the
failure and notifies subscribers on every state or error change.
`busy` = a command or scan refused because a transaction or a portal
pass is in flight. `internet_unreachable` = the internet check
received no HTTP response at all (transport error — no route, DNS
failure, connection refused or timeout); it is never
captive_portal, which requires a non-204 HTTP response. Reading
`Status` returns the current value without changing it.

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
| `factory_reset` | Emit `Status: factory_reset`, erase Wi-Fi config, VPN config, and the owner bond, then reboot. (Identity + device-secret survive; the printed label stays valid.) |
| `close_window` | End the provisioning window now (same end state as the 300 s timeout). |
| `vpn_stop` | Stop the VPN tunnel. Wi-Fi stays joined. Resulting state: online → online_no_vpn; vpn_failed → online_no_vpn (the committed-but-down vpn.conf stays stored); if no VPN is up, no-op success, state unchanged. |
| `vpn_start` | Start the VPN from the committed vpn.conf. Valid only from online_no_vpn (or vpn_failed, to retry): vpn_starting → online (commit check passes) or vpn_failed (check fails, Wi-Fi kept). Already online: no-op success. No committed vpn.conf: rejected, Status error=vpn_config_invalid, state unchanged. No committed Wi-Fi + internet up: rejected, Status error=busy, state unchanged. |
| `unbond` | Delete the owner bond, then disconnect. Device returns to the no-owner state; the next bonded peer becomes owner. |
| `portal_pass` | GRANT a 10-minute captive-portal pass. Valid only in state captive_portal with no pass active; while a pass is active, portal_pass is rejected with Status error=busy. Granting never re-runs the internet check. |
| `portal_recheck` | Re-run the internet check now (internet_check → online / captive_portal), whether or not a pass is active. This is the only re-check command; portal_pass never re-checks. |
| `diagnostics` | Build the diagnostics bundle on the device (`/etc/homesteadlink/diag.tar.gz`: journal last 24 h for hsl tags, state.json, `nft list ruleset`, `tailscale status`); the app downloads it from the config page (SPEC §F5) with the console-password token. |

Any other `cmd` value is rejected and changes nothing.

## 4. Chunking and reassembly

### 4.1 WifiScan (device → client)

1. A Read of `WifiScan` triggers a fresh scan (`Status: scanning`
   until results are ready or the 15 s scan timeout), discarding any
   previous result set. Clients must subscribe to notifications
   (CCCD) before reading, or results are missed. Subscribing alone
   never triggers a scan.
2. Each result is sent as one notification value (and is the value a
   subsequent Read returns, for the most recent result): one
   complete JSON object, at most the current ATT payload (§4.3), one
   AP per object, in `idx` order starting at 0.
3. The set is complete when the client has received the object with
   `idx = total − 1`. Objects may only be reassembled within one scan:
   a new Read, or a change in `total`, invalidates earlier objects.
   Duplicate `idx` values: the later object replaces the earlier one.
4. Empty scan: the device sends exactly one object
   `{"idx":0,"total":0,"ssid":"","bssid":"","rssi":0,"band":"2.4","channel":0,"security":"open","secure":false}` and returns
   `Status` to `idle`. `total:0` is the terminal marker; the other
   fields carry no meaning in that object.
5. Hidden APs (no broadcast SSID) are not reported in scan results.

### 4.2 Chunked writes (client → device)

Applies only when the JSON payload is larger than the current
payload (§4.3); a payload that fits the current payload is sent as a
single unchunked write with no header (see rule 2).

1. The client splits the UTF-8 JSON payload into chunks. Every chunk
   is one Write-with-response value of at most the current payload
   (§4.3): byte 0 is the sequence header `[seq]`, the remaining at
   most payload−1 bytes are the next payload bytes. `seq` is 1 byte,
   0-based, incrementing by 1 per chunk.
2. Discrimination: a first write whose first byte is `{` (0x7B) is an
   unchunked complete payload. In chunked mode the first write has
   `seq = 0`. (A JSON payload never begins with byte 0x00, so the two
   modes are unambiguous.)
3. The client sends chunks strictly in order, waiting for each write
   response before sending the next. Firmware appends payload bytes in
   `seq` order to a reassembly buffer.
4. End of payload: a chunk whose total value length is less than the
   current payload — i.e. carrying fewer than payload−1 payload
   bytes — is the final chunk. If the final chunk carries exactly
   payload−1 payload bytes (a full value), the client sends one extra
   terminating chunk: header only (`seq` = next value, zero payload
   bytes, value length 1).
5. On the final chunk, firmware parses the reassembled buffer as
   JSON and validates it against §3 (VpnConfig, ≤4096 B total)
   SYNCHRONOUSLY, on that write. Valid → config stored. Invalid,
   oversized or unparseable → nothing is stored and Status notifies
   `error=vpn_config_invalid` at once — validation errors are never
   deferred to the next VPN start attempt.
6. Reset conditions — buffer discarded, no config applied: a chunk
   with `seq = 0` (starts a new transfer), an out-of-order `seq`
   (≠ previous `seq` + 1), a disconnect, or a new unchunked write.
   There is no resume: the client restarts from `seq = 0`.
7. The same final-chunk validation applies to a chunked WifiConfig
   (§4.3): on the final chunk the reassembled buffer is parsed and
   validated against §3 (WifiConfig, ≤512 B) SYNCHRONOUSLY, on that
   write. Valid → config stored and the join sequence starts.
   Invalid, oversized or unparseable → nothing is stored, no join
   starts, and Status notifies `error=wifi_config_invalid` at once.

### 4.3 Payload rule (every characteristic, both directions)

payload = min(182, negotiated MTU − 3). Client → device: any write
value larger than the payload uses the §4.2 chunking — including
WifiConfig; no single write value exceeds the payload. Device →
client, READS: a read value MAY exceed the payload (DeviceInfo and
Status are ≤128 B; at payload 20 B they do not fit one value) — ATT
long-read (Read Blob / offset reads) carries the value in
payload-sized parts natively, and the client issues offset reads
until a short part returns. Device → client, NOTIFICATIONS (Status,
WifiScan): notifications cannot long-read, so a value larger than
the current payload is split into §4.2-format chunks (1-byte seq
header + at most payload−1 value bytes; the final-chunk rule of
§4.2 rule 4) sent as consecutive notifications, and the client
reassembles by seq exactly as in §4.2. WifiScan keeps one AP per
value, sized to the current payload; an AP object is never truncated
mid-JSON — if it cannot fit the payload it uses the same
notification chunking. Negotiated MTU < 23 → the app aborts
provisioning with 'BLE MTU too small' (§1); there is no other
fallback.

WifiConfig uses the §4.2 chunking whenever it exceeds the current
payload (§4.3). DeviceInfo and Status do NOT always fit one ATT
payload: at a small negotiated MTU they use the §4.3 read /
notification paths. No text in §3 or §4 states a fixed value size —
every value size in this contract is the current payload (§4.3).
(The §3 validation ceilings — WifiConfig ≤512 B, VpnConfig ≤4096 B
total — and the DeviceInfo/Status ≤128 B construction sizes are
validation/construction limits, not ATT value sizes, and stay.)
