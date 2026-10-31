package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// WifiConfigPayload is the §F4 WifiConfig JSON schema (≤512 B).
type WifiConfigPayload struct {
	SSID     string `json:"ssid"`
	PSK      string `json:"psk"`
	Country  string `json:"country"`
	Hidden   bool   `json:"hidden"`
	BSSID    string `json:"bssid,omitempty"`
	Security string `json:"security,omitempty"` // wpa2|wpa3|trans|eap|open (from scan)
}

// validateWifiPayload is the synchronous §4.2 rule-7 validation for a
// complete WifiConfig payload. Returns the payload and a contract
// error code ("" when valid).
func validateWifiPayload(b []byte) (*WifiConfigPayload, string) {
	if len(b) > 512 {
		return nil, "wifi_config_invalid"
	}
	var p WifiConfigPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, "wifi_config_invalid"
	}
	if len(p.SSID) == 0 || len(p.SSID) > 32 {
		return nil, "wifi_config_invalid"
	}
	if !validPSK(p.PSK) {
		return nil, "wifi_config_invalid"
	}
	return &p, ""
}

func wpaQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

func isHexPSK(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !('0' <= r && r <= '9' || 'a' <= r && r <= 'f' || 'A' <= r && r <= 'F') {
			return false
		}
	}
	return true
}

func validPSK(psk string) bool {
	if psk == "" {
		return true // open network
	}
	if isHexPSK(psk) {
		return true
	}
	return len(psk) >= 8 && len(psk) <= 63
}

// securityClass resolves the §F4 security matrix class for a config.
func securityClass(p WifiConfigPayload) string {
	switch strings.ToLower(p.Security) {
	case "wpa2", "wpa3", "trans", "eap", "open":
		return strings.ToLower(p.Security)
	}
	if p.PSK == "" {
		return "open"
	}
	return "wpa2"
}

// renderWpaConfig renders a wpa_supplicant config per the §F4 matrix:
// wpa2 → WPA-PSK; trans → WPA-PSK SAE pmf=1; wpa3 → SAE pmf=2;
// open → NONE; hidden → scan_ssid=1; bssid pinned when given.
func renderWpaConfig(p WifiConfigPayload) string {
	var b strings.Builder
	b.WriteString("ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev\n")
	b.WriteString("update_config=0\n")
	if p.Country != "" {
		fmt.Fprintf(&b, "country=%s\n", p.Country)
	}
	b.WriteString("\nnetwork={\n")
	fmt.Fprintf(&b, "\tssid=%s\n", wpaQuote(p.SSID))
	if p.BSSID != "" {
		fmt.Fprintf(&b, "\tbssid=%s\n", p.BSSID)
	}
	switch securityClass(p) {
	case "open":
		b.WriteString("\tkey_mgmt=NONE\n")
	case "wpa3":
		b.WriteString("\tkey_mgmt=SAE\n")
		b.WriteString("\tieee80211w=2\n")
		fmt.Fprintf(&b, "\tsae_password=%s\n", wpaQuote(p.PSK))
	case "trans":
		b.WriteString("\tkey_mgmt=WPA-PSK SAE\n")
		b.WriteString("\tieee80211w=1\n")
		writePSK(&b, p.PSK)
	default: // wpa2
		b.WriteString("\tkey_mgmt=WPA-PSK\n")
		writePSK(&b, p.PSK)
	}
	if p.Hidden {
		b.WriteString("\tscan_ssid=1\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func writePSK(b *strings.Builder, psk string) {
	if isHexPSK(psk) {
		fmt.Fprintf(b, "\tpsk=%s\n", psk)
	} else {
		fmt.Fprintf(b, "\tpsk=%s\n", wpaQuote(psk))
	}
}

func wpaCli(args ...string) (string, error) {
	full := append([]string{"-i", wifiIface}, args...)
	out, err := exec.Command("wpa_cli", full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func waitCompleted(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := wpaCli("status")
		if err == nil && strings.Contains(out, "wpa_state=COMPLETED") {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for wpa_state=COMPLETED")
}

// runDHCP: the DHCP client is systemd-networkd (§F4) — wait ≤20 s for
// its lease. Explicit clients remain available via HSL_DHCP_CLIENT.
func runDHCP(deadline time.Time) error {
	switch dhcpClient {
	case "dhclient":
		out, err := exec.Command("dhclient", "-1", wifiIface).CombinedOutput()
		if err != nil {
			return fmt.Errorf("dhclient failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	case "udhcpc":
		out, err := exec.Command("udhcpc", "-i", wifiIface, "-n", "-q", "-t", "5").CombinedOutput()
		if err != nil {
			return fmt.Errorf("udhcpc failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	default: // networkd: poll for lease + default route
		for time.Now().Before(deadline) {
			if ifaceIPv4() != "" && hasDefaultRoute() {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("networkd DHCP lease not seen within budget")
	}
}

func ifaceIPv4() string {
	iface, err := net.InterfaceByName(wifiIface)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

func hasDefaultRoute() bool {
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	return err == nil && strings.Contains(string(out), "default")
}

// captureUplinkDNS stores the wlan0 lease's DNS server in state.json
// as uplink_dns (§F4 portal bullet: provisiond resolves through it
// directly at portal-pass grant time, bypassing dnsmasq).
func captureUplinkDNS() {
	if dns := networkdLeaseDNS(); dns != "" {
		store.setUplinkDNS(dns)
		log.Printf("uplink_dns captured from networkd lease: %s", dns)
	}
}

func networkdLeaseDNS() string {
	idx, err := os.ReadFile("/sys/class/net/" + wifiIface + "/ifindex")
	if err != nil {
		return ""
	}
	b, err := os.ReadFile("/run/systemd/netif/leases/" + strings.TrimSpace(string(idx)))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "DNS=") {
			for _, f := range strings.Fields(strings.TrimPrefix(line, "DNS=")) {
				if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
					return f
				}
			}
		}
	}
	return ""
}

// --- Wi-Fi scan (§F4 WifiScan) ---

type ScanResult struct {
	Idx      int    `json:"idx"`
	Total    int    `json:"total"`
	SSID     string `json:"ssid"`
	BSSID    string `json:"bssid"`
	RSSI     int    `json:"rssi"`
	Band     string `json:"band"`
	Channel  int    `json:"channel"`
	Security string `json:"security"` // wpa2|wpa3|trans|eap|open
	Secure   bool   `json:"secure"`
}

func freqToChannel(freqMHz int) (string, int) {
	switch {
	case freqMHz >= 2412 && freqMHz <= 2484:
		if freqMHz == 2484 {
			return "2.4", 14
		}
		return "2.4", (freqMHz - 2407) / 5
	case freqMHz >= 5170 && freqMHz <= 5825:
		return "5", (freqMHz - 5000) / 5
	default:
		return "", 0
	}
}

func channelToFreq(band string, ch int) int {
	if band == "5" {
		return 5000 + ch*5
	}
	if ch == 14 {
		return 2484
	}
	return 2407 + ch*5
}

// scanSecurity classifies wpa_supplicant flags; `secure` follows the
// privacy capability (any WPA/RSN/SAE/EAP flag), not [ESS] (F21).
func scanSecurity(flags string) string {
	f := strings.ToUpper(flags)
	switch {
	case strings.Contains(f, "EAP"):
		return "eap"
	case strings.Contains(f, "SAE") && strings.Contains(f, "PSK"):
		return "trans"
	case strings.Contains(f, "SAE"):
		return "wpa3"
	case strings.Contains(f, "WPA") || strings.Contains(f, "RSN") || strings.Contains(f, "PSK"):
		return "wpa2"
	default:
		return "open"
	}
}

// parseScanResults parses wpa_cli scan_results. Hidden APs (empty
// SSID — no broadcast name) are FILTERED OUT (§4.1 rule 5).
func parseScanResults(out string) []ScanResult {
	var results []ScanResult
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 || f[0] == "bssid" {
			continue
		}
		if f[4] == "" {
			continue // hidden AP: never reported (§4.1 rule 5)
		}
		if seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		var rssi, freq int
		fmt.Sscanf(f[1], "%d", &freq)
		fmt.Sscanf(f[2], "%d", &rssi)
		band, ch := freqToChannel(freq)
		sec := scanSecurity(f[3])
		results = append(results, ScanResult{
			SSID: f[4], BSSID: f[0], RSSI: rssi, Band: band, Channel: ch,
			Security: sec, Secure: sec != "open",
		})
	}
	for i := range results {
		results[i].Idx = i
		results[i].Total = len(results)
	}
	return results
}

// scanWifi runs a scan bounded by the §F4 15 s scan timeout (polling
// scan_results until the BSS list appears — no fixed sleep).
func scanWifi() []ScanResult {
	_, _ = wpaCli("scan")
	deadline := time.Now().Add(15 * time.Second)
	var last []ScanResult
	for time.Now().Before(deadline) {
		time.Sleep(700 * time.Millisecond)
		out, err := wpaCli("scan_results")
		if err != nil {
			continue
		}
		last = parseScanResults(out)
		if len(last) > 0 {
			return last
		}
	}
	return last
}

// targetedScan is the §F4 directed scan for a typed/hidden SSID at
// transaction start (inside the join-phase budget — NOT the pre-write
// WifiScan): it finds the AP so the same security matrix and regdom
// channel comparison apply.
func targetedScan(ssid string, budget time.Duration) []ScanResult {
	_, _ = wpaCli("scan")
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		time.Sleep(600 * time.Millisecond)
		out, err := wpaCli("scan_results")
		if err != nil {
			continue
		}
		var hits []ScanResult
		for _, r := range parseScanResults(out) {
			if r.SSID == ssid {
				hits = append(hits, r)
			}
		}
		if len(hits) > 0 {
			return hits
		}
	}
	return nil
}

// renderScanValues renders one JSON value per AP. Values are never
// truncated mid-JSON: an oversized value goes out via the §4.3
// notification chunking in the notify path.
func renderScanValues(results []ScanResult) [][]byte {
	var vals [][]byte
	for _, r := range results {
		b, _ := json.Marshal(r)
		vals = append(vals, b)
	}
	if len(vals) == 0 {
		vals = append(vals, []byte(`{"idx":0,"total":0,"ssid":"","bssid":"","rssi":0,"band":"2.4","channel":0,"security":"open","secure":false}`))
	}
	return vals
}

// regdomChannelPermitted implements the §F4 regdom rule (the only v1
// signal): after country= is set, the target channel is compared
// against the permitted set from `iw reg get` for that country.
func regdomChannelPermitted(country string, band string, channel int) bool {
	if country == "" || channel == 0 {
		return true
	}
	out, err := exec.Command("iw", "reg", "get").CombinedOutput()
	if err != nil {
		log.Printf("regdom: iw reg get failed (%v) — cannot verify, allowing join", err)
		return true
	}
	freq := channelToFreq(band, channel)
	inBlock := false
	ranges := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "country ") {
			inBlock = strings.HasPrefix(line, "country "+strings.ToUpper(country)+":")
			continue
		}
		if !inBlock {
			continue
		}
		// "(2412 - 2462 @ 40), (N/A, 20), (0 ms), (N/A)"
		if !strings.HasPrefix(line, "(") {
			continue
		}
		var lo, hi int
		if _, err := fmt.Sscanf(line, "(%d - %d", &lo, &hi); err == nil {
			ranges++
			if freq >= lo && freq <= hi {
				return true
			}
		}
	}
	if ranges == 0 {
		log.Printf("regdom: no permitted ranges parsed for %s — allowing join", country)
		return true
	}
	return false
}

// --- Portal-pause plumbing shared with control.go (§F4) ---
//
// While a transaction (or the boot rejoin) sits in captive_portal,
// the 90 s budget is SUSPENDED: portal time never burns it. The
// paused party blocks on these channels; portal_recheck drives them.

var portalPause = struct {
	sync.Mutex
	kind     string // "tx" | "rejoin" | ""
	resumeCh chan struct{}
	abortCh  chan struct{}
}{}

func setPortalPause(kind string) (chan struct{}, chan struct{}) {
	portalPause.Lock()
	defer portalPause.Unlock()
	portalPause.kind = kind
	portalPause.resumeCh = make(chan struct{})
	portalPause.abortCh = make(chan struct{})
	return portalPause.resumeCh, portalPause.abortCh
}

func clearPortalPause() {
	portalPause.Lock()
	portalPause.kind = ""
	portalPause.resumeCh = nil
	portalPause.abortCh = nil
	portalPause.Unlock()
}

func portalPauseKind() string {
	portalPause.Lock()
	defer portalPause.Unlock()
	return portalPause.kind
}

// --- The §F4 apply-Wi-Fi transaction ---
//
// One 90 s ACTIVE-time budget (portal pause excluded): join 20 s →
// DHCP 20 s → internet check 20 s (NTP wait ≤10 s inside it) → VPN
// start 30 s. COMMIT POINT (Decision Log 43): wifi.conf commits the
// moment the internet check passes, BEFORE the VPN phase; vpn.conf
// commits when the VPN check passes OR fails (committed-but-down).
// At captive_portal NOTHING is committed — the transaction pauses
// with both files still candidate until portal_recheck passes.

func runWifiTransaction(p *WifiConfigPayload) {
	if !beginTx() {
		store.update(func(s *State) { s.Error = "busy" })
		log.Printf("wifi transaction refused: another transaction is in flight (busy)")
		return
	}
	defer endTx()
	if apModeOn() {
		stopAPMode()
	}
	start := time.Now()
	var pausedTotal time.Duration
	remaining := func() time.Duration {
		return time.Until(start.Add(90*time.Second + pausedTotal))
	}
	phaseCap := func(cap time.Duration) time.Duration {
		if r := remaining(); r < cap {
			return r
		}
		return cap
	}

	fingerprint("wifi psk", p.PSK)
	cls := securityClass(*p)
	targetBand, targetCh := "", 0
	if p.BSSID != "" {
		// Resolve the pinned AP's band/channel for the regdom rule.
		for _, r := range targetedScan(p.SSID, 4*time.Second) {
			if strings.EqualFold(r.BSSID, p.BSSID) {
				targetBand, targetCh = r.Band, r.Channel
				if p.Security == "" {
					cls = r.Security
				}
				break
			}
		}
	} else if p.Security == "" {
		// Typed SSID (no scan entry): targeted scan at transaction
		// start, inside the join budget (§F4 detection source).
		hits := targetedScan(p.SSID, 6*time.Second)
		if len(hits) > 0 {
			cls = hits[0].Security
			targetBand, targetCh = hits[0].Band, hits[0].Channel
		} else if !p.Hidden {
			store.set("idle", "wifi_config_invalid")
			log.Printf("wifi transaction: typed SSID %q not found by targeted scan — wifi_config_invalid, nothing stored", p.SSID)
			return
		}
		// hidden:true + not found: proceed with scan_ssid=1 (§F4).
	}
	if cls == "eap" {
		store.set("idle", "unsupported_eap")
		log.Printf("wifi transaction: EAP network rejected (unsupported_eap), nothing stored")
		return
	}
	pp := *p
	pp.Security = cls

	// Regdom before joining (§F4): country= + driver regdom, then the
	// channel comparison. A rejection is regdom_mismatch, never
	// auth_failed, and nothing is committed.
	if pp.Country != "" {
		if out, err := exec.Command("iw", "reg", "set", pp.Country).CombinedOutput(); err != nil {
			store.set("idle", "regdom_mismatch")
			log.Printf("wifi transaction: iw reg set %s failed: %v: %s", pp.Country, err, strings.TrimSpace(string(out)))
			return
		}
		if !regdomChannelPermitted(pp.Country, targetBand, targetCh) {
			store.set("idle", "regdom_mismatch")
			log.Printf("wifi transaction: target channel %d (%s) outside %s permitted set — regdom_mismatch, join not attempted", targetCh, targetBand, pp.Country)
			return
		}
	}

	candidate := renderWpaConfig(pp)
	prevLive, _ := os.ReadFile(wpaLiveConfig)
	hadPrev := prevLive != nil

	rollback := func(state, errCode string, cause error) {
		log.Printf("wifi transaction rolled back (%s/%s): %v", state, errCode, cause)
		store.setTxPhase("rolledback")
		_ = os.Remove(wifiCandPath)
		if b, err := os.ReadFile(vpnCandPath); err == nil {
			// The staged VPN goes with the transaction — loudly,
			// never silently (fingerprint only, never the value).
			var v VpnConfigPayload
			if json.Unmarshal(b, &v) == nil && v.Type == "tailscale" {
				fingerprint("discarded staged tailscale authkey", v.AuthKey)
			}
			log.Printf("wifi transaction rollback: discarding staged candidate vpn.conf with the transaction")
			_ = os.Remove(vpnCandPath)
		}
		if hadPrev {
			_ = writeFileAtomic(wpaLiveConfig, prevLive, 0o600)
		} else {
			_ = os.Remove(wpaLiveConfig)
		}
		_, _ = wpaCli("reconfigure")
		store.set(state, errCode)
		store.setTxPhase("")
	}

	store.setTxPhase("join")
	if err := writeFileAtomic(wifiCandPath, []byte(candidate), 0o600); err != nil {
		rollback("idle", "timeout", err)
		return
	}
	store.update(func(s *State) { s.State = "wifi_joining"; s.Error = ""; s.SSID = pp.SSID; s.IP4 = ""; s.VPN = false })
	if err := writeFileAtomic(wpaLiveConfig, []byte(candidate), 0o600); err != nil {
		rollback("idle", "timeout", err)
		return
	}
	if _, err := wpaCli("reconfigure"); err != nil {
		_ = exec.Command("systemctl", "restart", "wpa_supplicant@"+wifiIface+".service").Run()
	}
	joinErr := waitCompleted(phaseCap(20 * time.Second))
	if joinErr != nil && cls == "trans" {
		// §F4: a transition AP that rejects SAE falls back to WPA-PSK.
		log.Printf("transition AP rejected SAE join; retrying as WPA-PSK")
		pp.Security = "wpa2"
		candidate = renderWpaConfig(pp)
		_ = writeFileAtomic(wifiCandPath, []byte(candidate), 0o600)
		_ = writeFileAtomic(wpaLiveConfig, []byte(candidate), 0o600)
		_, _ = wpaCli("reconfigure")
		joinErr = waitCompleted(phaseCap(20 * time.Second))
	}
	if joinErr != nil {
		if out, _ := wpaCli("status"); strings.Contains(out, "WRONG_KEY") || strings.Contains(out, "auth_fail") {
			rollback("wifi_auth_failed", "auth_failed", joinErr)
		} else {
			rollback("idle", "timeout", joinErr)
		}
		return
	}

	store.setTxPhase("dhcp")
	store.set("dhcp", "")
	if err := runDHCP(time.Now().Add(phaseCap(20 * time.Second))); err != nil {
		rollback("dhcp", "dhcp_failed", err)
		return
	}
	ip := ifaceIPv4()
	if ip == "" || !hasDefaultRoute() {
		rollback("dhcp", "dhcp_failed", fmt.Errorf("no IPv4 lease or no default route after DHCP"))
		return
	}
	store.update(func(s *State) { s.IP4 = ip })
	captureUplinkDNS()

	// Internet check (20 s phase, NTP wait ≤10 s inside it).
	store.setTxPhase("internet_check")
	store.set("internet_check", "")
	waitNTPSynchronized(phaseCap(20 * time.Second))
	switch internetCheck() {
	case netUnreachable:
		// Transport error is NOT a portal (Decision Log 42):
		// before-commit failure → rollback, idle/internet_unreachable.
		rollback("idle", "internet_unreachable", fmt.Errorf("internet check: no HTTP response at all"))
		return
	case netPortal:
		store.set("captive_portal", "captive_portal")
		store.setTxPhase("portal_pause")
		resumeCh, abortCh := setPortalPause("tx")
		pauseStart := time.Now()
		log.Printf("wifi transaction PAUSED at captive_portal — 90s budget suspended until portal_recheck")
		select {
		case <-resumeCh:
			pausedTotal += time.Since(pauseStart)
			clearPortalPause()
			log.Printf("wifi transaction resumed after portal_recheck (paused %s, budget preserved)", time.Since(pauseStart).Round(time.Second))
		case <-abortCh:
			clearPortalPause()
			rollback("idle", "internet_unreachable", fmt.Errorf("internet check failed after portal pause"))
			return
		}
	}

	// COMMIT POINT (DL43): wifi.conf commits NOW, before the VPN phase.
	if err := os.Rename(wifiCandPath, wifiPath); err != nil {
		if err := writeFileAtomic(wifiPath, []byte(candidate), 0o600); err != nil {
			rollback("idle", "timeout", err)
			return
		}
		_ = os.Remove(wifiCandPath)
	}
	renderLiveFromCommitted()
	store.setTxPhase("committed")
	log.Printf("wifi transaction committed ssid=%q ip4=%s — VPN phase next", pp.SSID, ip)

	// VPN phase (30 s of the budget): a staged candidate vpn.conf is
	// raised and then committed EITHER WAY (DL43 committed-but-down);
	// a pre-existing committed vpn.conf is raised as part of the join
	// sequence; no VPN at all → online_no_vpn.
	store.setTxPhase("vpn")
	if _, err := os.Stat(vpnCandPath); err == nil {
		v, verr := loadStagedVPN()
		if verr != nil {
			store.set("vpn_failed", "vpn_config_invalid")
			commitStagedVPN()
		} else {
			_ = raiseAndValidateVPN(v) // sets online / vpn_failed
			commitStagedVPN()
		}
	} else if hasVPNConfig() {
		_ = raiseCommittedVPN()
	} else {
		store.set("online_no_vpn", "")
	}
	store.setTxPhase("")
}

// commitStagedVPN renames candidate/vpn.conf to the committed path
// (atomic, same filesystem) and re-renders live/.
func commitStagedVPN() {
	if err := os.Rename(vpnCandPath, vpnPath); err != nil {
		if b, rerr := os.ReadFile(vpnCandPath); rerr == nil {
			_ = writeFileAtomic(vpnPath, b, 0o600)
			_ = os.Remove(vpnCandPath)
		}
	}
	renderLiveFromCommitted()
}

func loadStagedVPN() (*VpnConfigPayload, error) {
	b, err := os.ReadFile(vpnCandPath)
	if err != nil {
		return nil, err
	}
	var v VpnConfigPayload
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// --- Boot rejoin (§F4 configured-device state machine) ---
//
// provisiond starts at idle (state never replayed). Committed join:
// 3 attempts (immediate, +5 s, +15 s), each wifi_joining → dhcp.
// Internet check: 204 → VPN step; portal → captive_portal pause (no
// VPN raise) until portal_recheck; transport error → idle +
// internet_unreachable with a 60 s re-check loop (Wi-Fi stays
// joined). All attempts failed → §F5 AP fallback, Status idle with
// the last failure in error.

var rejoinMu sync.Mutex
var rejoinRunning bool

func bootRejoin() {
	rejoinMu.Lock()
	if rejoinRunning {
		rejoinMu.Unlock()
		return
	}
	rejoinRunning = true
	rejoinMu.Unlock()
	defer func() {
		rejoinMu.Lock()
		rejoinRunning = false
		rejoinMu.Unlock()
	}()

	if !hasWifiConfig() {
		store.set("idle", "")
		startAPMode("no committed Wi-Fi config")
		return
	}
	ssid := committedSSID()
	var lastState, lastErr string
	joined := false
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt == 2 {
			time.Sleep(5 * time.Second)
		} else if attempt == 3 {
			time.Sleep(15 * time.Second)
		}
		log.Printf("boot rejoin attempt %d/3 ssid=%q", attempt, ssid)
		code, err := joinStoredWifiOnce(ssid)
		if err == nil {
			joined = true
			break
		}
		lastState, lastErr = code.state, code.errCode
		log.Printf("boot rejoin attempt %d failed (%s/%s): %v", attempt, lastState, lastErr, err)
	}
	if !joined {
		store.update(func(s *State) { s.SSID = "" ; s.IP4 = "" })
		store.set("idle", lastErr)
		startAPMode("committed join exhausted 3 boot attempts")
		return
	}
	captureUplinkDNS()
	rejoinInternetStep()
}

type joinFailure struct{ state, errCode string }

// joinStoredWifiOnce performs ONE join+DHCP attempt from the
// committed wifi.conf and classifies failures for the rejoin machine.
func joinStoredWifiOnce(ssid string) (joinFailure, error) {
	b, err := os.ReadFile(wifiPath)
	if err != nil {
		return joinFailure{"idle", "timeout"}, err
	}
	if err := writeFileAtomic(wpaLiveConfig, b, 0o600); err != nil {
		return joinFailure{"idle", "timeout"}, err
	}
	if _, err := wpaCli("reconfigure"); err != nil {
		_ = exec.Command("systemctl", "restart", "wpa_supplicant@"+wifiIface+".service").Run()
	}
	store.update(func(s *State) { s.State = "wifi_joining"; s.Error = ""; s.SSID = ssid })
	if err := waitCompleted(20 * time.Second); err != nil {
		if out, _ := wpaCli("status"); strings.Contains(out, "WRONG_KEY") || strings.Contains(out, "auth_fail") {
			store.set("wifi_auth_failed", "auth_failed")
			return joinFailure{"wifi_auth_failed", "auth_failed"}, err
		}
		store.set("idle", "timeout")
		return joinFailure{"idle", "timeout"}, err
	}
	store.set("dhcp", "")
	if err := runDHCP(time.Now().Add(20 * time.Second)); err != nil {
		store.set("dhcp", "dhcp_failed")
		return joinFailure{"dhcp", "dhcp_failed"}, err
	}
	ip := ifaceIPv4()
	if ip == "" {
		store.set("dhcp", "dhcp_failed")
		return joinFailure{"dhcp", "dhcp_failed"}, fmt.Errorf("no IPv4 lease after DHCP")
	}
	store.update(func(s *State) { s.IP4 = ip })
	return joinFailure{}, nil
}

// rejoinInternetStep runs the internet check for a joined boot and
// routes to the VPN step, the portal pause, or the 60 s
// internet_unreachable re-check loop.
func rejoinInternetStep() {
	store.set("internet_check", "")
	waitNTPSynchronized(10 * time.Second)
	switch internetCheck() {
	case netOK:
		vpnStep()
	case netPortal:
		store.set("captive_portal", "captive_portal")
		setPortalPause("rejoin")
		log.Printf("boot rejoin paused at captive_portal — no VPN raise until portal_recheck passes")
	case netUnreachable:
		store.set("idle", "internet_unreachable")
		log.Printf("boot rejoin: internet unreachable (transport error) — Wi-Fi stays joined, re-checking every 60s")
		go rejoinRecheckLoop()
	}
}

// rejoinRecheckLoop re-runs the internet check every 60 s after a
// boot transport error; on 204 the rejoin continues at the VPN step.
func rejoinRecheckLoop() {
	for {
		time.Sleep(60 * time.Second)
		if store.get().State != "idle" || store.get().Error != "internet_unreachable" {
			return // state moved on (new transaction, reset, …)
		}
		switch internetCheck() {
		case netOK:
			log.Printf("boot rejoin: internet check now passes — continuing at the VPN step")
			vpnStep()
			return
		case netPortal:
			store.set("captive_portal", "captive_portal")
			setPortalPause("rejoin")
			return
		}
	}
}

// vpnStep is the boot-rejoin VPN step (§F4): a committed vpn.conf is
// raised + validated (online / vpn_failed, Wi-Fi kept, NO AP
// fallback); no vpn.conf → online_no_vpn.
func vpnStep() {
	if hasVPNConfig() {
		if err := raiseCommittedVPN(); err != nil {
			log.Printf("boot rejoin vpn step: %v", err)
		}
		return
	}
	store.set("online_no_vpn", "")
}

// committedSSID extracts the ssid= value from the committed (rendered)
// wifi.conf for Status reporting.
func committedSSID() string {
	b, err := os.ReadFile(wifiPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ssid=") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "ssid="))
			return strings.Trim(v, "\"")
		}
	}
	return ""
}

// --- AP fallback (§F5; owner: hsl-provisiond executes every step) ---

var apMu sync.Mutex
var apOn bool

func apModeOn() bool {
	apMu.Lock()
	defer apMu.Unlock()
	return apOn
}

// startAPMode performs the §F5 STA→AP switch: stop wpa_supplicant,
// networkd stand-down via a /run override, flush + assign
// 192.168.65.1/24, install the AP dnsmasq section, start hostapd.
func startAPMode(reason string) {
	apMu.Lock()
	if apOn {
		apMu.Unlock()
		return
	}
	apOn = true
	apMu.Unlock()
	log.Printf("AP fallback starting (%s)", reason)
	_ = exec.Command("systemctl", "stop", "wpa_supplicant@"+wifiIface+".service").Run()
	_ = os.MkdirAll("/run/systemd/network", 0o755)
	_ = writeFileAtomic("/run/systemd/network/30-wlan0.network",
		[]byte("[Match]\nName="+wifiIface+"\n\n[Network]\nDHCP=no\n"), 0o644)
	_ = exec.Command("networkctl", "reload").Run()
	_ = exec.Command("ip", "addr", "flush", "dev", wifiIface).Run()
	_ = exec.Command("ip", "addr", "add", "192.168.65.1/24", "dev", wifiIface).Run()
	if b, err := os.ReadFile("/opt/homesteadlink/configs/dnsmasq-ap.conf"); err == nil {
		_ = writeFileAtomic("/etc/dnsmasq.d/dnsmasq-ap.conf", b, 0o644)
	} else {
		log.Printf("AP fallback: dnsmasq-ap.conf missing from /opt/homesteadlink/configs: %v", err)
	}
	_ = exec.Command("systemctl", "restart", "dnsmasq.service").Run()
	if out, err := exec.Command("systemctl", "start", "hostapd.service").CombinedOutput(); err != nil {
		log.Printf("AP fallback: hostapd start failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

// stopAPMode reverses the §F5 switch (AP → STA): stop hostapd,
// remove the AP dnsmasq section, flush wlan0, drop the /run networkd
// override, start wpa_supplicant@wlan0 (networkd re-runs DHCP).
func stopAPMode() {
	apMu.Lock()
	if !apOn {
		apMu.Unlock()
		return
	}
	apOn = false
	apMu.Unlock()
	log.Printf("AP fallback stopping — returning wlan0 to STA mode")
	_ = exec.Command("systemctl", "stop", "hostapd.service").Run()
	_ = os.Remove("/etc/dnsmasq.d/dnsmasq-ap.conf")
	_ = exec.Command("systemctl", "restart", "dnsmasq.service").Run()
	_ = exec.Command("ip", "addr", "flush", "dev", wifiIface).Run()
	_ = os.Remove("/run/systemd/network/30-wlan0.network")
	_ = exec.Command("networkctl", "reload").Run()
	_ = exec.Command("systemctl", "start", "wpa_supplicant@"+wifiIface+".service").Run()
}
