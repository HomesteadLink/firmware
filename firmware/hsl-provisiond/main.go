// hsl-provisiond — HomeSteadyLink provisioning daemon (spec §F4).
// Single static arm64 binary, no cgo. BlueZ GATT server over D-Bus,
// wpa_supplicant Wi-Fi transactions, WireGuard/Tailscale VPN raise,
// nftables kill switch (loaded by nftables.service; provisiond only
// verifies it and edits the portal_pass chain), captive-portal
// handling, AP fallback + config page.
package main

import (
	"crypto/hmac"
	"fmt"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cfgDir           = "/etc/homesteadlink"
	candidateDir     = cfgDir + "/candidate"
	liveDir          = cfgDir + "/live"
	statePath        = cfgDir + "/state.json"
	identityPath     = cfgDir + "/identity.json"
	deviceSecretPath = cfgDir + "/device-secret"
	wifiPath         = cfgDir + "/wifi.conf"
	wifiCandPath     = candidateDir + "/wifi.conf"
	vpnPath          = cfgDir + "/vpn.conf"
	vpnCandPath      = candidateDir + "/vpn.conf"
	modelName        = "HomeSteadyLink Zero2W"
	defaultFW        = "1.1.0"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	wpaLiveConfig = envOr("HSL_WPA_CONFIG", liveDir+"/wpa_supplicant.conf")
	wifiIface     = envOr("HSL_WIFI_IFACE", "wlan0")
	// DHCP client for wlan0 is systemd-networkd (§F4): provisiond only
	// waits for the lease. HSL_DHCP_CLIENT=udhcpc|dhclient restores the
	// legacy explicit-client behaviour on non-networkd images.
	dhcpClient   = envOr("HSL_DHCP_CLIENT", "networkd")
	wgConfigPath = envOr("HSL_WG_CONFIG", liveDir+"/wg-hsl.conf")
	versionFile  = envOr("HSL_VERSION_FILE", "/opt/homesteadlink/VERSION")
	dnsmasqConf  = envOr("HSL_DNSMASQ_CONF", "/etc/dnsmasq.d/homesteadlink.conf")
	diagPath     = envOr("HSL_DIAG_PATH", cfgDir+"/diag.tar.gz")
	fwVersion    = defaultFW
)

func init() {
	if b, err := os.ReadFile(versionFile); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			fwVersion = v
		}
	}
}

// fingerprint is the only permitted log representation of a secret:
// length + first 4 bytes of its SHA-256. Values are never logged.
func fingerprint(label, secret string) {
	sum := sha256.Sum256([]byte(secret))
	log.Printf("%s received len=%d sha256[0:4]=%s", label, len(secret), hex.EncodeToString(sum[:4]))
}

// --- Identity (§F1: board serial; three domain-separated derivations) ---

type Identity struct {
	Serial         string `json:"serial"`
	SetupCode      string `json:"setup_code"`
	ConsolePass    string `json:"console_password"`
	APPassphrase   string `json:"ap_passphrase,omitempty"`
}

// boardSerial is the H618 SoC serial from the device tree. arm64
// /proc/cpuinfo has no Serial field; the SD CID and the hostname are
// NEVER serial sources (§F1).
func boardSerial() string {
	b, err := os.ReadFile("/proc/device-tree/serial-number")
	if err != nil {
		return ""
	}
	return strings.Trim(strings.TrimSpace(string(b)), "\x00")
}

// loadDeviceSecret is READ-ONLY (§F1 / §F8 item 10(xvii)):
// device-secret creation belongs to hsl-firstboot ONLY. provisiond
// never creates or rewrites it — a missing/short secret is a loud
// error, not a silent regeneration (a regenerated secret would
// silently move every derived credential away from the label).
func loadDeviceSecret() ([]byte, error) {
	b, err := os.ReadFile(deviceSecretPath)
	if err != nil {
		return nil, err
	}
	if len(b) < 16 {
		return nil, fmt.Errorf("device-secret too short: %d bytes", len(b))
	}
	return b, nil
}

func hmacSHA256(secret []byte, msg string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

// setupCodeFor is the pinned §F1 derivation: the first 3 bytes of
// HMAC-SHA256(secret, serial) as a big-endian 24-bit integer,
// mod 1,000,000, zero-padded to 6 digits.
func setupCodeFor(secret []byte, serial string) string {
	sum := hmacSHA256(secret, serial)
	n := uint32(sum[0])<<16 | uint32(sum[1])<<8 | uint32(sum[2])
	return padInt(int(n % 1000000), 6)
}

// consolePasswordFor (§F1): "HSL-" + first 4 bytes of
// HMAC-SHA256(secret, serial+":console") as BE uint32 mod 10^8,
// zero-padded to 8 digits. This is the root password and the §F5
// config-page token — a SEPARATE secret from the setup code.
func consolePasswordFor(secret []byte, serial string) string {
	sum := hmacSHA256(secret, serial+":console")
	n := binary.BigEndian.Uint32(sum[:4])
	return "HSL-" + padInt(int(n % 100000000), 8)
}

// apPassphraseFor (§F1): first 5 bytes of
// HMAC-SHA256(secret, serial+":ap") as a BE 40-bit integer
// mod 10^12, zero-padded to 12 digits. Domain-separated from the
// setup code: knowing the serial (public) or the setup code gives an
// attacker nothing (Decision Log entry 33).
func apPassphraseFor(secret []byte, serial string) string {
	sum := hmacSHA256(secret, serial+":ap")
	var n uint64
	for i := 0; i < 5; i++ {
		n = n<<8 | uint64(sum[i])
	}
	return padInt(int(n % 1000000000000), 12)
}

func padInt(n, width int) string {
	s := strconv.Itoa(n)
	for len(s) < width {
		s = "0" + s
	}
	return s
}

// loadIdentity implements §F1: identity follows the BOARD.
// READ-ONLY (§F8 item 10(xvii)): identity.json + device-secret are
// created and persisted by hsl-firstboot ONLY (it runs every boot,
// Before=hsl-provisiond.service). provisiond derives the same
// pinned values in memory from the persisted secret + serial and
// writes NOTHING: no identity creation, no rewrite on board-serial
// change (firstboot's next run owns that), no random fallback.
func loadIdentity() Identity {
	stored := Identity{}
	if b, err := os.ReadFile(identityPath); err == nil {
		_ = json.Unmarshal(b, &stored)
	}
	serial := boardSerial()
	if serial == "" {
		serial = stored.Serial
	}
	if serial == "" {
		log.Printf("identity: ERROR — no board serial and no persisted identity.json; hsl-firstboot has not created an identity and provisiond will not invent one (§F8 10(xvii))")
	}
	secret, err := loadDeviceSecret()
	if err != nil {
		log.Printf("identity: device secret unavailable: %v", err)
		return Identity{Serial: serial, SetupCode: stored.SetupCode}
	}
	return Identity{
		Serial:       serial,
		SetupCode:    setupCodeFor(secret, serial),
		ConsolePass:  consolePasswordFor(secret, serial),
		APPassphrase: apPassphraseFor(secret, serial),
	}
}

func last4(s string) string {
	if len(s) <= 4 {
		return s
	}
	return s[len(s)-4:]
}

// uptimeSeconds is the powered-time clock (CLOCK_BOOTTIME via
// /proc/uptime): the only clock the §F4 window and lockout rules use.
// Wall clock is never used for either (no RTC, no NTP pre-provisioning).
func uptimeSeconds() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	return f
}

// --- State (§F4 Status schema) + persisted extras ---

type State struct {
	State string `json:"state"`
	Error string `json:"error"`
	SSID  string `json:"ssid"`
	IP4   string `json:"ip4"`
	VPN   bool   `json:"vpn"`
}

// MarshalJSON renders the contract Status shape: error, ssid and ip4
// are null (not "") until set, and vpn is a boolean.
func (st State) MarshalJSON() ([]byte, error) {
	nullable := func(v string) interface{} {
		if v == "" {
			return nil
		}
		return v
	}
	return json.Marshal(map[string]interface{}{
		"state": st.State,
		"error": nullable(st.Error),
		"ssid":  nullable(st.SSID),
		"ip4":   nullable(st.IP4),
		"vpn":   st.VPN,
	})
}

func (st *State) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	str := func(k string) string {
		var v string
		_ = json.Unmarshal(raw[k], &v)
		return v
	}
	st.State, st.Error, st.SSID, st.IP4 = str("state"), str("error"), str("ssid"), str("ip4")
	var vb bool
	if err := json.Unmarshal(raw["vpn"], &vb); err == nil {
		st.VPN = vb
	} else {
		st.VPN = str("vpn") != ""
	}
	return nil
}

// lockoutState is the §F4 pairing lockout in its powered-time form:
// remaining durations counted down on the monotonic clock and
// persisted; wall clock is NEVER used (Decision Log entry 41).
type lockoutState struct {
	PairFailures         int `json:"pair_failures"`
	PairWindowRemainingS int `json:"pair_window_remaining_s"`
	LockoutCount         int `json:"lockout_count"`
	LockoutRemainingS    int `json:"lockout_remaining_s"`
}

// persistedState is the state.json document. Per §F4/§F8 it persists
// CONFIG + COUNTERS ONLY (transaction phase, pairing-lockout
// counters, uplink_dns). The operational Status state is NEVER
// persisted or replayed: it is re-derived at boot by the §F4
// boot-rejoin machine, starting from idle.
type persistedState struct {
	Lockout   lockoutState `json:"lockout"`
	TxPhase   string       `json:"tx_phase"`
	UplinkDNS string       `json:"uplink_dns,omitempty"`
}

type stateStore struct {
	mu        sync.Mutex
	st        State
	lk        lockoutState
	txPhase   string
	uplinkDNS string
	onChange  func(State)
}

func (s *stateStore) set(state, errStr string) {
	s.mu.Lock()
	s.st.State = state
	s.st.Error = errStr
	st := s.st
	s.mu.Unlock()
	if s.onChange != nil {
		s.onChange(st)
	}
	log.Printf("state=%s error=%q ssid=%q ip4=%q vpn=%v", st.State, st.Error, st.SSID, st.IP4, st.VPN)
}

func (s *stateStore) update(fn func(*State)) {
	s.mu.Lock()
	fn(&s.st)
	st := s.st
	s.mu.Unlock()
	if s.onChange != nil {
		s.onChange(st)
	}
}

func (s *stateStore) get() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *stateStore) setTxPhase(phase string) {
	s.mu.Lock()
	s.txPhase = phase
	s.mu.Unlock()
	s.persist()
}

func (s *stateStore) getTxPhase() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txPhase
}

func (s *stateStore) setUplinkDNS(dns string) {
	s.mu.Lock()
	s.uplinkDNS = dns
	s.mu.Unlock()
	s.persist()
}

func (s *stateStore) getUplinkDNS() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uplinkDNS
}

// json renders Status ≤128 B. On overflow the SSID is shortened FIRST;
// the error code is never dropped (F15).
func (s *stateStore) json() []byte {
	st := s.get()
	b, _ := json.Marshal(st)
	for len(b) > 128 && len(st.SSID) > 0 {
		st.SSID = st.SSID[:len(st.SSID)-1]
		b, _ = json.Marshal(st)
	}
	if len(b) > 128 { // last resort: drop ssid, keep state+error
		st.SSID = ""
		b, _ = json.Marshal(st)
	}
	return b
}

// persist writes state.json atomically: tmp + fsync + rename + dir fsync.
func (s *stateStore) persist() {
	s.mu.Lock()
	doc := persistedState{Lockout: s.lk, TxPhase: s.txPhase, UplinkDNS: s.uplinkDNS}
	s.mu.Unlock()
	b, err := json.Marshal(doc)
	if err != nil {
		return
	}
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		return
	}
	tmp := statePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return
	}
	f.Close()
	if err := os.Rename(tmp, statePath); err != nil {
		return
	}
	if d, err := os.Open(cfgDir); err == nil {
		d.Sync()
		d.Close()
	}
}

// load reads ONLY the persisted config + counters. The operational
// Status always starts at idle and is re-derived by the boot-rejoin
// machine — a previous boot's state is never replayed (§F8 item 10x).
func (s *stateStore) load() {
	s.st = State{State: "idle"}
	b, err := os.ReadFile(statePath)
	if err != nil {
		return
	}
	var doc persistedState
	if err := json.Unmarshal(b, &doc); err == nil {
		s.lk, s.txPhase, s.uplinkDNS = doc.Lockout, doc.TxPhase, doc.UplinkDNS
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if f, err := os.OpenFile(tmp, os.O_RDWR, perm); err == nil {
		f.Sync()
		f.Close()
	}
	return os.Rename(tmp, path)
}

func hasWifiConfig() bool {
	_, err := os.Stat(wifiPath)
	return err == nil
}

// --- Wi-Fi/VPN transaction gate (§F4: one transaction at a time) ---

var txMu sync.Mutex
var txActive bool

func beginTx() bool {
	txMu.Lock()
	defer txMu.Unlock()
	if txActive {
		return false
	}
	txActive = true
	return true
}

func endTx() {
	txMu.Lock()
	txActive = false
	txMu.Unlock()
}

func isTxActive() bool {
	txMu.Lock()
	defer txMu.Unlock()
	return txActive
}

var (
	identity Identity
	store    = &stateStore{}
	btDead   bool
)

// bootRecovery implements the §F4 crash rules + the round-8 crash
// rule (B2):
//   - candidate/wifi.conf is discarded (the device boots the
//     committed config or stays unconfigured — never half-applied);
//   - PROMOTION BRANCH: a candidate/vpn.conf whose transaction had
//     PASSED the wifi commit point (persisted tx_phase "committed"
//     or "vpn", committed wifi.conf present) is PROMOTED to the
//     committed vpn.conf — as committed-but-down (DL43): the boot
//     rejoin raises it and lands online or vpn_failed. It is never
//     deleted.
//   - a candidate/vpn.conf from a transaction that never reached
//     the wifi commit point is discarded with the transaction
//     (loudly journal-logged, fingerprint only);
//   - an invalid candidate/vpn.conf is discarded loudly and the
//     failure is surfaced in the initial Status error;
//   - live/ is re-rendered from committed; tx_phase resets.
//
// The promotion branch is exactly why the transaction phase is
// persisted in state.json: §F4's crash/restart rule mandates it
// ("the transaction phase is persisted in state.json on every phase
// change; if the commit rename already happened, finish the apply
// from committed"). Without the persisted phase, "passed the wifi
// commit point" is unknowable at boot.
func bootRecovery() {
	phase := store.getTxPhase()
	if phase != "" && phase != "committed" && phase != "rolledback" {
		log.Printf("boot recovery: transaction interrupted in phase %q — discarding candidate wifi, booting committed config", phase)
	}
	if b, err := os.ReadFile(vpnCandPath); err == nil {
		_, code := validateVpnPayload(b)
		switch {
		case code != "":
			log.Printf("boot recovery: staged candidate vpn.conf INVALID (%s) — discarding, surfaced as Status error", code)
			store.update(func(s *State) { s.Error = code })
		case (phase == "committed" || phase == "vpn") && hasWifiConfig():
			// Promotion: the wifi commit point had passed, so the
			// staged VPN belongs to a committed transaction.
			if err := writeFileAtomic(vpnPath, b, 0o600); err == nil {
				log.Printf("boot recovery: candidate vpn.conf PROMOTED to committed-but-down (transaction had passed the wifi commit point, phase=%q)", phase)
			}
		default:
			var v VpnConfigPayload
			if json.Unmarshal(b, &v) == nil && v.Type == "tailscale" {
				fingerprint("discarded pre-commit staged tailscale authkey", v.AuthKey)
			}
			log.Printf("boot recovery: staged candidate vpn.conf discarded — its transaction never reached the wifi commit point (phase=%q)", phase)
		}
	}
	_ = os.RemoveAll(candidateDir)
	_ = os.MkdirAll(candidateDir, 0o755)
	_ = os.MkdirAll(liveDir, 0o755)
	renderLiveFromCommitted()
	store.setTxPhase("")
}

// renderLiveFromCommitted regenerates live/ (wpa_supplicant.conf,
// wg-hsl.conf) from the committed wifi.conf / vpn.conf.
func renderLiveFromCommitted() {
	if b, err := os.ReadFile(wifiPath); err == nil {
		_ = writeFileAtomic(wpaLiveConfig, b, 0o600)
	}
	if v, err := loadVPN(); err == nil && v.Type == "wireguard" {
		_ = writeFileAtomic(wgConfigPath, []byte(v.Conf), 0o600)
	}
}

// lockoutTicker counts the §F4 pairing window and lockout down on
// powered time: every 5 s it decrements the remaining durations,
// persists at least every 10 s while anything is counting, and
// persists immediately when a duration reaches zero. When the
// 60-minute failure window expires, pair_failures resets (a fresh
// window opens at the next failure). lockout_count persists across
// windows and power-cycles; it resets only on a successful bond or a
// factory reset.
func lockoutTicker() {
	var sincePersist time.Duration
	for {
		time.Sleep(5 * time.Second)
		sincePersist += 5 * time.Second
		store.mu.Lock()
		changed := false
		flushNow := false
		if store.lk.LockoutRemainingS > 0 {
			store.lk.LockoutRemainingS -= 5
			changed = true
			if store.lk.LockoutRemainingS <= 0 {
				store.lk.LockoutRemainingS = 0
				flushNow = true
				log.Printf("pairing lockout expired (powered time); bonding re-enabled, lockout_count=%d persists", store.lk.LockoutCount)
			}
		}
		if store.lk.PairWindowRemainingS > 0 {
			store.lk.PairWindowRemainingS -= 5
			changed = true
			if store.lk.PairWindowRemainingS <= 0 {
				store.lk.PairWindowRemainingS = 0
				store.lk.PairFailures = 0
				flushNow = true
			}
		}
		store.mu.Unlock()
		if changed && (flushNow || sincePersist >= 10*time.Second) {
			store.persist()
			sincePersist = 0
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("") // journald adds the unit/tag (SyslogIdentifier=hsl-provisiond)
	identity = loadIdentity()
	store.load()
	bootRecovery()
	log.Printf("hsl-provisiond %s starting serial_last4=%s model=%q", fwVersion, last4(identity.Serial), modelName)

	// Kill switch (§F4): the merged ruleset is installed at
	// /etc/nftables.conf and loaded by nftables.service at boot.
	// provisiond loads NO table of its own (§F8 item 10) — it only
	// verifies presence; a missing ruleset is LOUD and every VPN
	// raise refuses until it appears (fail closed).
	if err := verifyKillSwitch(); err != nil {
		log.Printf("FATAL: nftables kill switch (inet hsl_filter) not in place: %v — vpn raise blocked until nftables.service loads it", err)
	}

	go btSupervision()
	go lockoutTicker()
	go provisioningWindowManager()
	go apFallbackServer()

	gatt, err := startGATT()
	if err != nil {
		log.Printf("GATT server failed to start: %v (daemon continues; AP fallback remains)", err)
	} else {
		defer gatt.Close()
	}

	// Boot rejoin (§F4): the state machine derives Status from idle;
	// an unconfigured device starts the §F5 AP fallback instead.
	go bootRejoin()

	select {} // serve forever; systemd owns lifecycle
}
