package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// WifiConfigPayload is the §F4 WifiConfig JSON schema (≤512 B).
// bssid and security are the updated-spec optional fields.
type WifiConfigPayload struct {
	SSID     string `json:"ssid"`
	PSK      string `json:"psk"`
	Country  string `json:"country"`
	Hidden   bool   `json:"hidden"`
	BSSID    string `json:"bssid,omitempty"`
	Security string `json:"security,omitempty"` // wpa2|wpa3|trans|eap|open (from scan)
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

func vpnEndpointHost() string {
	v, err := loadVPN()
	if err != nil {
		return os.Getenv("HSL_VPN_ENDPOINT")
	}
	if v.Type == "wireguard" {
		for _, line := range strings.Split(v.Conf, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "endpoint") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					hostport := strings.TrimSpace(parts[1])
					if i := strings.LastIndex(hostport, ":"); i > 0 {
						return strings.Trim(hostport[:i], "[]")
					}
					return hostport
				}
			}
		}
	}
	return os.Getenv("HSL_VPN_ENDPOINT")
}

// reachabilityCheck verifies the VPN endpoint host (not generic
// internet); with no VPN configured it probes the gateway instead.
func reachabilityCheck() error {
	host := vpnEndpointHost()
	if host == "" {
		out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
		if err != nil {
			return fmt.Errorf("no vpn endpoint and no default route")
		}
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				host = fields[i+1]
				break
			}
		}
		if host == "" {
			return fmt.Errorf("no vpn endpoint and no gateway")
		}
	}
	if err := exec.Command("ping", "-c", "1", "-W", "3", host).Run(); err == nil {
		return nil
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 3*time.Second)
	if err == nil {
		conn.Close()
		return nil
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return fmt.Errorf("vpn endpoint %s unreachable (timeout)", host)
	}
	return nil // connection refused etc. = host reachable
}

func remaining(deadline time.Time, phase time.Duration) time.Duration {
	rem := time.Until(deadline)
	if rem < phase {
		return rem
	}
	return phase
}

// applyWifiTransaction is the §F4 apply transaction under ONE 90 s
// total budget: candidate → reconfigure → join 20 s → DHCP 20 s →
// reachability → commit (candidate → committed, live re-rendered) or
// roll back to the committed block with the paired state+error.
func applyWifiTransaction(payload []byte) error {
	if !beginTx() {
		store.update(func(s *State) { s.Error = "busy" })
		return fmt.Errorf("wifi transaction already in progress (busy)")
	}
	defer endTx()
	deadline := time.Now().Add(90 * time.Second)

	var p WifiConfigPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("wifi config JSON: %w", err)
	}
	if p.SSID == "" {
		return fmt.Errorf("wifi config: ssid empty")
	}
	if securityClass(p) == "eap" {
		store.set("idle", "unsupported_eap")
		return fmt.Errorf("wifi config: 802.1X/EAP not supported in v1 (unsupported_eap)")
	}
	if !validPSK(p.PSK) {
		store.set("wifi_auth_failed", "auth_failed")
		return fmt.Errorf("wifi config: psk must be 8-63 ASCII or 64 hex chars")
	}
	fingerprint("wifi psk", p.PSK)

	// Regulatory domain before joining (§F4): a regdom failure reports
	// regdom_mismatch, never auth_failed.
	if p.Country != "" {
		if out, err := exec.Command("iw", "reg", "set", p.Country).CombinedOutput(); err != nil {
			store.set("idle", "regdom_mismatch")
			return fmt.Errorf("iw reg set %s: %v: %s", p.Country, err, strings.TrimSpace(string(out)))
		}
	}

	candidate := renderWpaConfig(p)
	prevLive, _ := os.ReadFile(wpaLiveConfig)
	hadPrev := prevLive != nil

	store.setTxPhase("join")
	if err := writeFileAtomic(wifiCandPath, []byte(candidate), 0o600); err != nil {
		return err
	}
	store.update(func(s *State) { s.State = "wifi_joining"; s.Error = ""; s.SSID = p.SSID })

	fail := func(state, errCode string, cause error) error {
		log.Printf("wifi transaction failed (%s/%s): %v — rolling back", state, errCode, cause)
		store.setTxPhase("rolledback")
		_ = os.Remove(wifiCandPath)
		if hadPrev {
			_ = writeFileAtomic(wpaLiveConfig, prevLive, 0o600)
		} else {
			_ = os.Remove(wpaLiveConfig)
		}
		_, _ = wpaCli("reconfigure")
		store.set(state, errCode)
		return fmt.Errorf("%s: %w", errCode, cause)
	}

	if err := writeFileAtomic(wpaLiveConfig, []byte(candidate), 0o600); err != nil {
		return fail("idle", "timeout", err)
	}
	if _, err := wpaCli("reconfigure"); err != nil {
		_ = exec.Command("systemctl", "restart", "wpa_supplicant@"+wifiIface+".service").Run()
	}
	joinErr := waitCompleted(remaining(deadline, 20*time.Second))
	if joinErr != nil && securityClass(p) == "trans" {
		// §F4: a transition AP that rejects SAE falls back to WPA-PSK.
		log.Printf("transition AP rejected SAE join; retrying as WPA-PSK")
		p.Security = "wpa2"
		candidate = renderWpaConfig(p)
		_ = writeFileAtomic(wifiCandPath, []byte(candidate), 0o600)
		_ = writeFileAtomic(wpaLiveConfig, []byte(candidate), 0o600)
		_, _ = wpaCli("reconfigure")
		joinErr = waitCompleted(remaining(deadline, 20*time.Second))
	}
	if joinErr != nil {
		if out, _ := wpaCli("status"); strings.Contains(out, "WRONG_KEY") || strings.Contains(out, "auth_fail") {
			return fail("wifi_auth_failed", "auth_failed", joinErr)
		}
		return fail("idle", "timeout", joinErr)
	}

	store.setTxPhase("dhcp")
	store.set("dhcp", "")
	dhcpDeadline := deadline
	if d := time.Now().Add(20 * time.Second); d.Before(dhcpDeadline) {
		dhcpDeadline = d
	}
	if err := runDHCP(dhcpDeadline); err != nil {
		return fail("dhcp", "dhcp_failed", err)
	}
	ip := ifaceIPv4()
	if ip == "" || !hasDefaultRoute() {
		return fail("dhcp", "dhcp_failed", fmt.Errorf("no IPv4 lease or no default route after DHCP"))
	}
	store.update(func(s *State) { s.IP4 = ip })

	store.setTxPhase("internet_check")
	if err := reachabilityCheck(); err != nil {
		return fail("idle", "timeout", err)
	}

	// Commit: candidate → committed wifi.conf, live/ re-rendered.
	if err := os.Rename(wifiCandPath, wifiPath); err != nil {
		if err := writeFileAtomic(wifiPath, []byte(candidate), 0o600); err != nil {
			return err
		}
		_ = os.Remove(wifiCandPath)
	}
	renderLiveFromCommitted()
	store.setTxPhase("committed")
	log.Printf("wifi transaction committed ssid=%q ip4=%s", p.SSID, ip)
	store.set("internet_check", "")
	return nil
}

// joinStoredWifi reconfigures wpa_supplicant from the committed
// wifi.conf (boot path) and waits for a lease (networkd by default).
func joinStoredWifi() error {
	b, err := os.ReadFile(wifiPath)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(wpaLiveConfig, b, 0o600); err != nil {
		return err
	}
	if _, err := wpaCli("reconfigure"); err != nil {
		_ = exec.Command("systemctl", "restart", "wpa_supplicant@"+wifiIface+".service").Run()
	}
	store.set("wifi_joining", "")
	if err := waitCompleted(20 * time.Second); err != nil {
		store.set("idle", "timeout")
		return err
	}
	store.set("dhcp", "")
	if err := runDHCP(time.Now().Add(20 * time.Second)); err != nil {
		store.set("dhcp", "dhcp_failed")
		return err
	}
	if ip := ifaceIPv4(); ip != "" {
		store.update(func(s *State) { s.IP4 = ip })
	}
	return nil
}

// --- Wi-Fi scan (§F4 WifiScan, updated fields) ---

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

func scanWifi() []ScanResult {
	_, _ = wpaCli("scan")
	time.Sleep(2 * time.Second)
	out, err := wpaCli("scan_results")
	if err != nil {
		return nil
	}
	var results []ScanResult
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 || f[0] == "bssid" {
			continue
		}
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

// scanChunks renders scan results as ≤182 B JSON chunks (ATT payload at MTU 185).
func scanChunks() [][]byte {
	results := scanWifi()
	var chunks [][]byte
	for _, r := range results {
		b, _ := json.Marshal(r)
		for len(b) > 182 && len(r.SSID) > 0 { // pathological SSID: truncate until it fits
			r.SSID = r.SSID[:len(r.SSID)/2]
			b, _ = json.Marshal(r)
		}
		chunks = append(chunks, b)
	}
	if len(chunks) == 0 {
		chunks = append(chunks, []byte(`{"idx":0,"total":0,"ssid":"","bssid":"","rssi":0,"band":"","channel":0,"security":"open","secure":false}`))
	}
	return chunks
}
