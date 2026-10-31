// hsl-provisiond — HomeSteadyLink provisioning daemon (spec §F4).
// Single static arm64 binary, no cgo. BlueZ GATT server over D-Bus,
// wpa_supplicant Wi-Fi transactions, WireGuard/Tailscale VPN raise,
// nftables kill switch, captive-portal detection, AP fallback page.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	cfgDir       = "/etc/homesteadlink"
	statePath    = cfgDir + "/state.json"
	identityPath = cfgDir + "/identity.json"
	wifiPath     = cfgDir + "/wifi.conf"
	wifiCandPath = cfgDir + "/wifi.candidate.conf"
	vpnPath      = cfgDir + "/vpn.json"
	fwVersion    = "1.0.0"
	modelName    = "HomeSteadyLink Zero2W"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	wpaLiveConfig = envOr("HSL_WPA_CONFIG", "/etc/wpa_supplicant/wpa_supplicant.conf")
	wifiIface     = envOr("HSL_WIFI_IFACE", "wlan0")
	dhcpClient    = envOr("HSL_DHCP_CLIENT", "udhcpc") // or "dhclient"
	nftFile       = envOr("HSL_NFT_FILE", cfgDir+"/nftables.conf")
	wgConfigPath  = envOr("HSL_WG_CONFIG", "/etc/wireguard/wg-hsl.conf")
)

// fingerprint is the only permitted log representation of a secret:
// length + first 4 bytes of its SHA-256. Values are never logged.
func fingerprint(label, secret string) {
	sum := sha256.Sum256([]byte(secret))
	log.Printf("%s received len=%d sha256[0:4]=%s", label, len(secret), hex.EncodeToString(sum[:4]))
}

type Identity struct {
	Serial    string `json:"serial"`
	SetupCode string `json:"setup_code"`
}

func loadIdentity() Identity {
	if b, err := os.ReadFile(identityPath); err == nil {
		var id Identity
		if json.Unmarshal(b, &id) == nil && id.Serial != "" {
			return id
		}
	}
	// Fallback (§F1): /proc/cpuinfo Serial, else SD CID.
	id := Identity{Serial: deriveSerial()}
	return id
}

func deriveSerial() string {
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Serial") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					if s := strings.TrimSpace(parts[1]); s != "" {
						return s
					}
				}
			}
		}
	}
	for _, p := range []string{"/sys/block/mmcblk0/device/cid", "/sys/block/mmcblk1/device/cid", "/sys/block/mmcblk2/device/cid"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	if hn, err := os.Hostname(); err == nil {
		return hn
	}
	return "unknown"
}

func last4(s string) string {
	if len(s) <= 4 {
		return s
	}
	return s[len(s)-4:]
}

// --- State (§F4 Status characteristic schema) ---

type State struct {
	State string `json:"state"`
	Error string `json:"error"`
	SSID  string `json:"ssid"`
	IP4   string `json:"ip4"`
	VPN   bool   `json:"vpn"`
}

// MarshalJSON renders the §F4/gatt-contract Status shape: error, ssid and
// ip4 are null (not "") until set, and vpn is a boolean.
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

// UnmarshalJSON accepts the contract shape above and the legacy internal
// shape (vpn as a string like "wireguard") from older state.json files.
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

type stateStore struct {
	mu       sync.Mutex
	st       State
	onChange func(State)
}

func (s *stateStore) set(state, errStr string) {
	s.mu.Lock()
	s.st.State = state
	s.st.Error = errStr
	st := s.st
	s.mu.Unlock()
	persistState(st)
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
	persistState(st)
	if s.onChange != nil {
		s.onChange(st)
	}
}

func (s *stateStore) get() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *stateStore) json() []byte {
	b, _ := json.Marshal(s.get())
	if len(b) > 128 { // §F4: Status JSON ≤128 B — truncate error text first
		st := s.get()
		st.Error = ""
		b, _ = json.Marshal(st)
	}
	return b
}

// persistState writes state.json atomically: tmp + fsync + rename + dir fsync.
func persistState(st State) {
	b, err := json.Marshal(st)
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

func loadState() State {
	var st State
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.State == "" {
		st.State = "idle"
	}
	return st
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

var (
	identity Identity
	store    = &stateStore{}
	bootTime = time.Now()
	btDead   bool
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("") // journald adds the unit/tag (SyslogIdentifier=hsl-provisiond)
	identity = loadIdentity()
	store.st = loadState()
	log.Printf("hsl-provisiond %s starting serial_last4=%s model=%q", fwVersion, last4(identity.Serial), modelName)

	// Kill switch first (§F4: applied at startup, before VPN, removed never).
	if err := applyKillSwitch(); err != nil {
		log.Printf("nftables kill switch apply failed: %v (continuing; forward stays default-drop only if table loaded)", err)
	}

	go btSupervision()
	go provisioningWindowManager()
	go apFallbackServer()

	gatt, err := startGATT()
	if err != nil {
		log.Printf("GATT server failed to start: %v (daemon continues; AP fallback remains)", err)
	} else {
		defer gatt.Close()
	}

	// If a committed config exists, bring the link/VPN back up.
	if hasWifiConfig() {
		go func() {
			if err := joinStoredWifi(); err != nil {
				log.Printf("stored wifi rejoin failed: %v", err)
				return
			}
			checkCaptiveAndVPN()
		}()
	} else {
		store.set("idle", "")
	}

	select {} // serve forever; systemd owns lifecycle
}
