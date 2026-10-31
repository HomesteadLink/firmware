package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// VpnConfigPayload is the §F4 VpnConfig JSON schema (≤4096 B reassembled,
// updated spec amendment 1).
type VpnConfigPayload struct {
	Type     string `json:"type"` // "wireguard" | "tailscale"
	Conf     string `json:"conf"` // wireguard: full wg-quick config text
	AuthKey  string `json:"authkey"`
	ExitNode string `json:"exit_node"`
}

const vpnConfigCeiling = 4096

func loadVPN() (*VpnConfigPayload, error) {
	b, err := os.ReadFile(vpnPath)
	if err != nil {
		return nil, err
	}
	var v VpnConfigPayload
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func hasVPNConfig() bool {
	_, err := os.Stat(vpnPath)
	return err == nil
}

// validateWireGuardFullTunnel (§F4): [Interface] with PrivateKey +
// Address and ≥1 [Peer] whose AllowedIPs includes 0.0.0.0/0.
func validateWireGuardFullTunnel(conf string) bool {
	section := ""
	hasKey, hasAddr, fullTunnel := false, false, false
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch {
		case section == "[interface]" && k == "privatekey" && v != "":
			hasKey = true
		case section == "[interface]" && k == "address" && v != "":
			hasAddr = true
		case section == "[peer]" && k == "allowedips":
			for _, cidr := range strings.Split(v, ",") {
				if strings.TrimSpace(cidr) == "0.0.0.0/0" {
					fullTunnel = true
				}
			}
		}
	}
	return hasKey && hasAddr && fullTunnel
}

func wgDNS(conf string) string {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if k, v, found := strings.Cut(line, "="); found && strings.EqualFold(strings.TrimSpace(k), "DNS") {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	return ""
}

// validateVpnPayload validates a complete VpnConfig payload. The
// returned error code is a contract error string ("" when valid).
func validateVpnPayload(payload []byte) (*VpnConfigPayload, string) {
	if len(payload) > vpnConfigCeiling {
		return nil, "vpn_config_invalid"
	}
	var v VpnConfigPayload
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil, "vpn_config_invalid"
	}
	switch v.Type {
	case "wireguard":
		if v.Conf == "" {
			return nil, "vpn_config_invalid"
		}
		if !validateWireGuardFullTunnel(v.Conf) {
			return nil, "vpn_not_full_tunnel"
		}
	case "tailscale":
		if v.AuthKey == "" {
			return nil, "vpn_config_invalid"
		}
	default:
		return nil, "vpn_config_invalid"
	}
	return &v, ""
}

// applyVpnConfig persists a validated VpnConfig payload (0600). It does
// NOT raise the VPN and never touches Status by itself (F2): the caller
// decides whether the §F4 raise+validation may run.
func applyVpnConfig(payload []byte) error {
	v, code := validateVpnPayload(payload)
	if code != "" {
		return fmt.Errorf("vpn config invalid: %s", code)
	}
	if v.Type == "wireguard" {
		fingerprint("wireguard conf", v.Conf)
	} else {
		fingerprint("tailscale authkey", v.AuthKey)
	}
	if err := writeFileAtomic(vpnCandPath, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(vpnCandPath, vpnPath); err != nil {
		return err
	}
	renderLiveFromCommitted()
	return nil
}

// wifiOnline reports whether Wi-Fi is joined with a lease — the
// precondition for any VPN raise that may publish `online` (F2).
func wifiOnline() bool {
	st := store.get()
	return st.SSID != "" && st.IP4 != ""
}

// raiseAndValidateVPN is the only path that may set `online` (§F4):
// raise, then prove the tunnel — WireGuard handshake ≤20 s + default
// route via wg-hsl, or Tailscale BackendState=Running + netcheck UDP.
// Failure lands in state vpn_failed with the paired error.
func raiseAndValidateVPN() error {
	if !wifiOnline() {
		return fmt.Errorf("wifi not online; vpn raise deferred")
	}
	if err := applyKillSwitch(); err != nil {
		store.set("vpn_failed", "vpn_failed")
		return fmt.Errorf("kill switch not in place, refusing vpn raise: %w", err)
	}
	v, err := loadVPN()
	if err != nil {
		return fmt.Errorf("no vpn config stored: %w", err)
	}
	store.set("vpn_starting", "")
	switch v.Type {
	case "wireguard":
		if err := writeFileAtomic(wgConfigPath, []byte(v.Conf), 0o600); err != nil {
			store.set("vpn_failed", "vpn_failed")
			return err
		}
		out, err := exec.Command("systemctl", "start", "wg-quick@wg-hsl.service").CombinedOutput()
		if err != nil {
			store.set("vpn_failed", "vpn_failed")
			return fmt.Errorf("wg-quick@wg-hsl start: %v: %s", err, strings.TrimSpace(string(out)))
		}
		if err := waitWGHandshake(20 * time.Second); err != nil {
			store.set("vpn_failed", "vpn_failed")
			return err
		}
		if !defaultRouteVia("wg-hsl") {
			store.set("vpn_failed", "vpn_failed")
			return fmt.Errorf("no default route via wg-hsl after raise")
		}
		// R3-2: an actual ping THROUGH the tunnel gates `online`,
		// not just handshake recency + route presence.
		if err := pingThroughTunnel("wg-hsl", wgDNS(v.Conf)); err != nil {
			store.set("vpn_failed", "vpn_failed")
			return fmt.Errorf("tunnel ping failed: %w", err)
		}
		setDNSUpstream(wgDNS(v.Conf))
	case "tailscale":
		// Auth key via a 0600 file (file: scheme), never argv (F19).
		keyFile := cfgDir + "/.ts-authkey"
		if err := writeFileAtomic(keyFile, []byte(v.AuthKey), 0o600); err != nil {
			store.set("vpn_failed", "vpn_failed")
			return err
		}
		defer os.Remove(keyFile)
		args := []string{"up", "--authkey", "file:" + keyFile, "--accept-dns=false"} // R3-2: dnsmasq owns DNS (server=100.100.100.100); tailscale must not take over DNS
		if v.ExitNode != "" {
			args = append(args, "--exit-node", v.ExitNode)
		}
		fingerprint("tailscale authkey", v.AuthKey)
		if _, err := exec.Command("tailscale", args...).CombinedOutput(); err != nil {
			store.set("vpn_failed", "vpn_failed")
			return fmt.Errorf("tailscale up failed: %v", err)
		}
		if err := waitTailscaleRunning(20 * time.Second); err != nil {
			code := "vpn_failed"
			if tailscaleKeyExpired() {
				code = "authkey_expired"
			}
			store.set("vpn_failed", code)
			return fmt.Errorf("tailscale validation: %v", err)
		}
		setDNSUpstream("100.100.100.100")
	}
	store.update(func(s *State) { s.VPN = true })
	store.set("online", "")
	log.Printf("vpn up and validated type=%s", v.Type)
	return nil
}

// pingThroughTunnel sends ICMP through the tunnel interface to the
// config's DNS resolver (or 1.1.1.1) — proof of end-to-end forwarding.
func pingThroughTunnel(iface, target string) error {
	if target == "" {
		target = "1.1.1.1"
	}
	out, err := exec.Command("ping", "-I", iface, "-c", "2", "-W", "3", target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ping -I %s %s: %v: %s", iface, target, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func waitWGHandshake(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("wg", "show", "wg-hsl", "latest-handshakes").CombinedOutput()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					if ts, err := strconv.ParseInt(f[1], 10, 64); err == nil && ts > 0 &&
						time.Since(time.Unix(ts, 0)) <= timeout+5*time.Second {
						return nil
					}
				}
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("no wireguard handshake within %s", timeout)
}

func defaultRouteVia(dev string) bool {
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	return err == nil && strings.Contains(string(out), "dev "+dev)
}

type tailscaleStatus struct {
	BackendState string `json:"BackendState"`
}

func tailscaleBackendState() string {
	out, err := exec.Command("tailscale", "status", "--json").CombinedOutput()
	if err != nil {
		return ""
	}
	var st tailscaleStatus
	if json.Unmarshal(out, &st) != nil {
		return ""
	}
	return st.BackendState
}

func tailscaleKeyExpired() bool {
	out, _ := exec.Command("tailscale", "status").CombinedOutput()
	s := strings.ToLower(string(out))
	return strings.Contains(s, "expired") || strings.Contains(s, "needs login") ||
		strings.Contains(s, "logged out")
}

func waitTailscaleRunning(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tailscaleBackendState() == "Running" {
			out, err := exec.Command("tailscale", "netcheck").CombinedOutput()
			if err == nil && strings.Contains(string(out), "UDP: true") {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("tailscale BackendState/netcheck not healthy within %s", timeout)
}

// startVPN is kept for callers that only need the raise attempt; all
// state publication goes through raiseAndValidateVPN / checkCaptiveAndVPN.
func startVPN() error { return raiseAndValidateVPN() }

func stopVPN() error {
	v, err := loadVPN()
	if err == nil {
		switch v.Type {
		case "wireguard":
			_ = exec.Command("systemctl", "stop", "wg-quick@wg-hsl.service").Run()
		case "tailscale":
			_ = exec.Command("tailscale", "down").Run()
		}
	} else {
		_ = exec.Command("systemctl", "stop", "wg-quick@wg-hsl.service").Run()
	}
	setDNSUpstream("")
	store.update(func(s *State) { s.VPN = false })
	// Wi-Fi stays joined (§F4): the no-VPN terminal state is
	// online_no_vpn when a lease is held, idle otherwise (F20 resolved
	// by the updated contract's online_no_vpn state).
	if wifiOnline() {
		store.set("online_no_vpn", "")
	} else {
		store.set("idle", "")
	}
	return nil
}

// setDNSUpstream owns the dnsmasq server= line at runtime (§F4 DNS
// plumbing): VPN up → the VPN resolver; VPN down → no upstream at all
// (queries get no answer instead of leaking). Restarts dnsmasq.
func setDNSUpstream(server string) {
	b, err := os.ReadFile(dnsmasqConf)
	if err != nil {
		log.Printf("dnsmasq conf unreadable, cannot set upstream: %v", err)
		return
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "server=") {
			continue
		}
		lines = append(lines, line)
	}
	out := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	if server != "" {
		out += "server=" + server + "\n"
	}
	if err := writeFileAtomic(dnsmasqConf, []byte(out), 0o644); err != nil {
		log.Printf("dnsmasq upstream write failed: %v", err)
		return
	}
	_ = exec.Command("systemctl", "restart", "dnsmasq.service").Run()
	log.Printf("dnsmasq upstream set to %q (empty = fail-closed)", server)
}

// mergedRuleset is the §F4 kill switch: ONE ruleset, also shipped as
// firmware/configs/nftables.conf and installed to /etc/nftables.conf.
const mergedRuleset = `table inet hsl_filter {
 chain forward {
  type filter hook forward priority 0; policy drop;
  ct state established,related accept
  jump portal_pass
  iifname "usb0" oifname { "wg-hsl", "tailscale0", "tun0" } accept
  iifname "wlan0" oifname { "wg-hsl", "tailscale0", "tun0" } accept
 }
 chain portal_pass {
 }
 chain input {
  type filter hook input priority 0; policy accept;
 }
}
table ip hsl_nat {
 chain postrouting {
  type nat hook postrouting priority 100; policy accept;
  ip saddr 192.168.64.0/24 oifname { "wg-hsl", "tailscale0", "tun0" } masquerade
  ip saddr 192.168.65.0/24 oifname { "wg-hsl", "tailscale0", "tun0" } masquerade
 }
}
`

// applyKillSwitch loads the merged ruleset from /etc/nftables.conf
// (nftables.service owns boot loading; this is the daemon's verify /
// re-apply). provisiond never loads a private table of its own (F5).
func applyKillSwitch() error {
	if _, err := os.Stat(nftFile); err == nil {
		out, err := exec.Command("nft", "-f", nftFile).CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft -f %s: %v: %s", nftFile, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(mergedRuleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft load merged ruleset: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func killSwitchInPlace() bool { return applyKillSwitch() == nil }

// portalPass (§F4, F4-fix): resolve the connectivity-check host and the
// portal redirect target, insert destination-scoped accepts into the
// hsl_filter portal_pass chain (source usb0 only, tcp 80/443 only),
// journal-log IPs + expiry, auto-delete after exactly 10 min.
func portalPass() {
	ips := map[string]bool{}
	checkHost := "connectivitycheck.gstatic.com"
	if addrs, err := net.LookupIP(checkHost); err == nil {
		for _, a := range addrs {
			if a.To4() != nil {
				ips[a.String()] = true
			}
		}
	}
	// Follow the portal redirect target (if any) and resolve it too.
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if resp, err := client.Get("http://" + checkHost + "/generate_204"); err == nil {
		loc := resp.Header.Get("Location")
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if loc != "" {
			if u, err := net.LookupIP(hostOf(loc)); err == nil {
				for _, a := range u {
					if a.To4() != nil {
						ips[a.String()] = true
					}
				}
			}
			log.Printf("portal_pass: redirect target %s", loc)
		}
	}
	if len(ips) == 0 {
		log.Printf("portal_pass: no portal IPs resolved; no hole opened")
		return
	}
	var set []string
	for ip := range ips {
		set = append(set, ip)
	}
	expiry := time.Now().Add(10 * time.Minute)
	rule := fmt.Sprintf("iifname \"usb0\" ip daddr { %s } tcp dport { 80, 443 } accept comment \"hsl-portal-pass\"",
		strings.Join(set, ", "))
	add := exec.Command("nft", append([]string{"add", "rule", "inet", "hsl_filter", "portal_pass"}, strings.Fields(rule)...)...)
	// strings.Fields would split the quoted comment/set braces wrongly;
	// pass the rule as a single -f snippet instead.
	_ = add
	snippet := fmt.Sprintf("add rule inet hsl_filter portal_pass %s\n", rule)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(snippet)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("portal_pass add failed: %v: %s", err, strings.TrimSpace(string(out)))
		return
	}
	portalGrantUntil = expiry
	log.Printf("portal_pass: granted dst=%v tcp 80/443 from usb0 only, expires %s", set, expiry.Format(time.RFC3339))
	go func() {
		time.Sleep(10 * time.Minute)
		removePortalPass()
		portalGrantUntil = time.Time{}
		log.Printf("portal_pass: temporary exception expired and removed")
	}()
}

func hostOf(rawurl string) string {
	s := rawurl
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/:?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

var handleRe = regexp.MustCompile(`handle (\d+)`)

var portalGrantUntil time.Time

func portalGrantActive() bool { return time.Now().Before(portalGrantUntil) }

func removePortalPass() {
	out, err := exec.Command("nft", "-a", "list", "chain", "inet", "hsl_filter", "portal_pass").CombinedOutput()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "hsl-portal-pass") {
			if m := handleRe.FindStringSubmatch(line); m != nil {
				_ = exec.Command("nft", "delete", "rule", "inet", "hsl_filter", "portal_pass", "handle", m[1]).Run()
			}
		}
	}
}

// waitNTPSynchronized implements the §F4 clock rule: ≤10 s wait for
// systemd-timesyncd before the internet check.
func waitNTPSynchronized() {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").CombinedOutput()
		if err == nil && strings.TrimSpace(string(out)) == "yes" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Printf("clock not NTPSynchronized after 10s; proceeding with internet check")
}

// checkCaptive does the §F4 connectivity check after DHCP.
func checkCaptive() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://connectivitycheck.gstatic.com/generate_204")
	if err != nil {
		return true // unreachable counts as not-clean internet
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode != 204
}

// checkCaptiveAndVPN runs after a successful join: NTP wait, captive
// check, then the VPN raise+validation — the only route to `online`.
// With no VPN config the terminal state is online_no_vpn (F2).
func checkCaptiveAndVPN() {
	waitNTPSynchronized()
	if checkCaptive() {
		store.set("captive_portal", "captive_portal")
		log.Printf("captive portal detected (non-204 from generate_204); kill switch stays up")
		return
	}
	if hasVPNConfig() {
		if err := raiseAndValidateVPN(); err != nil {
			log.Printf("vpn raise/validation failed: %v", err)
		}
		return
	}
	store.set("online_no_vpn", "")
}
