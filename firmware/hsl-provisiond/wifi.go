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
type WifiConfigPayload struct {
	SSID    string `json:"ssid"`
	PSK     string `json:"psk"`
	Country string `json:"country"`
	Hidden  bool   `json:"hidden"`
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

// renderWpaConfig renders a complete wpa_supplicant config for one network.
func renderWpaConfig(p WifiConfigPayload) string {
	var b strings.Builder
	b.WriteString("ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev\n")
	b.WriteString("update_config=0\n")
	if p.Country != "" {
		fmt.Fprintf(&b, "country=%s\n", p.Country)
	}
	b.WriteString("\nnetwork={\n")
	fmt.Fprintf(&b, "\tssid=%s\n", wpaQuote(p.SSID))
	if p.PSK == "" {
		b.WriteString("\tkey_mgmt=NONE\n")
	} else {
		fmt.Fprintf(&b, "\tpsk=%s\n", wpaQuote(p.PSK))
	}
	if p.Hidden {
		b.WriteString("\tscan_ssid=1\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func wpaCli(args ...string) (string, error) {
	full := append([]string{"-i", wifiIface}, args...)
	out, err := exec.Command("wpa_cli", full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// waitCompleted polls wpa_supplicant status until COMPLETED or timeout.
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

func runDHCP() error {
	var cmd *exec.Cmd
	switch dhcpClient {
	case "dhclient":
		cmd = exec.Command("dhclient", "-1", wifiIface)
	default: // udhcpc
		cmd = exec.Command("udhcpc", "-i", wifiIface, "-n", "-q", "-t", "5")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %v: %s", dhcpClient, err, strings.TrimSpace(string(out)))
	}
	return nil
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

// reachabilityCheck verifies the VPN endpoint host (not generic internet):
// for WireGuard, the Endpoint host in the stored config; otherwise the
// configured HSL_VPN_ENDPOINT host. TCP/UDP probe = ICMP ping + DNS/TCP dial.
func reachabilityCheck() error {
	host := vpnEndpointHost()
	if host == "" {
		// No VPN configured yet: fall back to gateway ping so the Wi-Fi
		// transaction can still commit (VPN raise happens separately).
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
	// ICMP may be filtered; a TCP dial to any port proves L3 reachability
	// if it gets past SYN (refused still proves the host is reachable).
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

// applyWifiTransaction is the §F4 apply transaction:
// candidate file → reconfigure → 20 s COMPLETED + DHCP + route +
// VPN-endpoint reachability → commit to wifi.conf, or rollback.
func applyWifiTransaction(payload []byte) error {
	var p WifiConfigPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("wifi config JSON: %w", err)
	}
	if p.SSID == "" {
		return fmt.Errorf("wifi config: ssid empty")
	}
	fingerprint("wifi psk", p.PSK)
	candidate := renderWpaConfig(p)

	// Snapshot previous live config for rollback.
	prevLive, _ := os.ReadFile(wpaLiveConfig)
	hadPrev := prevLive != nil

	if err := writeFileAtomic(wifiCandPath, []byte(candidate), 0o600); err != nil {
		return err
	}
	store.update(func(s *State) { s.State = "wifi_joining"; s.Error = ""; s.SSID = p.SSID })

	// fail rolls back and reports with the contract state+error pair:
	// auth rejection -> wifi_auth_failed/auth_failed, DHCP failure ->
	// dhcp/dhcp_failed, everything else -> idle/timeout.
	fail := func(state, errCode string, cause error) error {
		log.Printf("wifi transaction failed (%s/%s): %v — rolling back", state, errCode, cause)
		if hadPrev {
			_ = writeFileAtomic(wpaLiveConfig, prevLive, 0o600)
		} else {
			_ = os.Remove(wpaLiveConfig)
		}
		_, _ = wpaCli("reconfigure")
		store.set(state, errCode)
		return fmt.Errorf("%s: %w", errCode, cause)
	}

	// Install candidate as the live wpa_supplicant config and reconfigure.
	if err := writeFileAtomic(wpaLiveConfig, []byte(candidate), 0o600); err != nil {
		return fail("idle", "timeout", err)
	}
	if _, err := wpaCli("reconfigure"); err != nil {
		// wpa_supplicant may not be running yet; start via systemd once.
		_ = exec.Command("systemctl", "restart", "wpa_supplicant.service").Run()
	}
	if err := waitCompleted(20 * time.Second); err != nil {
		// Distinguish auth failure from plain timeout when wpa reports it.
		if out, _ := wpaCli("status"); strings.Contains(out, "WRONG_KEY") || strings.Contains(out, "auth_fail") {
			return fail("wifi_auth_failed", "auth_failed", err)
		}
		return fail("idle", "timeout", err)
	}

	store.set("dhcp", "")
	if err := runDHCP(); err != nil {
		return fail("dhcp", "dhcp_failed", err)
	}
	ip := ifaceIPv4()
	if ip == "" || !hasDefaultRoute() {
		return fail("dhcp", "dhcp_failed", fmt.Errorf("no IPv4 lease or no default route after DHCP"))
	}
	store.update(func(s *State) { s.IP4 = ip })

	if err := reachabilityCheck(); err != nil {
		return fail("idle", "timeout", err)
	}

	// Commit: candidate becomes the stored wifi.conf.
	if err := writeFileAtomic(wifiPath, []byte(candidate), 0o600); err != nil {
		return err
	}
	_ = os.Remove(wifiCandPath)
	log.Printf("wifi transaction committed ssid=%q ip4=%s", p.SSID, ip)
	store.set("internet_check", "")
	return nil
}

// joinStoredWifi reconfigures wpa_supplicant from the committed wifi.conf
// (boot path / rollback path) and waits for a lease.
func joinStoredWifi() error {
	b, err := os.ReadFile(wifiPath)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(wpaLiveConfig, b, 0o600); err != nil {
		return err
	}
	if _, err := wpaCli("reconfigure"); err != nil {
		_ = exec.Command("systemctl", "restart", "wpa_supplicant.service").Run()
	}
	store.set("wifi_joining", "")
	if err := waitCompleted(20 * time.Second); err != nil {
		store.set("idle", "timeout")
		return err
	}
	store.set("dhcp", "")
	if err := runDHCP(); err != nil {
		return err
	}
	if ip := ifaceIPv4(); ip != "" {
		store.update(func(s *State) { s.IP4 = ip })
	}
	return nil
}

// --- Wi-Fi scan (§F4 WifiScan) ---

type ScanResult struct {
	Idx    int    `json:"idx"`
	Total  int    `json:"total"`
	SSID   string `json:"ssid"`
	RSSI   int    `json:"rssi"`
	Secure bool   `json:"secure"`
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
		var rssi int
		fmt.Sscanf(f[2], "%d", &rssi)
		results = append(results, ScanResult{
			SSID:   f[4],
			RSSI:   rssi,
			Secure: !strings.Contains(f[3], "[ESS]") || strings.Contains(f[3], "WPA") || strings.Contains(f[3], "RSN"),
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
		for len(b) > 182 { // pathological SSID: truncate SSID until it fits
			r.SSID = r.SSID[:len(r.SSID)/2]
			b, _ = json.Marshal(r)
		}
		chunks = append(chunks, b)
	}
	if len(chunks) == 0 {
		chunks = append(chunks, []byte(`{"idx":0,"total":0,"ssid":"","rssi":0,"secure":false}`))
	}
	return chunks
}
