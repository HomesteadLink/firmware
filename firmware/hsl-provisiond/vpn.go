package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// VpnConfigPayload is the §F4 VpnConfig JSON schema (≤2048 B reassembled).
type VpnConfigPayload struct {
	Type     string `json:"type"` // "wireguard" | "tailscale"
	Conf     string `json:"conf"` // wireguard: full wg-quick config text
	AuthKey  string `json:"authkey"`
	ExitNode string `json:"exit_node"`
}

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

// applyVpnConfig persists a VpnConfig payload (0600) and raises the VPN.
func applyVpnConfig(payload []byte) error {
	var v VpnConfigPayload
	if err := json.Unmarshal(payload, &v); err != nil {
		return fmt.Errorf("vpn config JSON: %w", err)
	}
	switch v.Type {
	case "wireguard":
		if v.Conf == "" {
			return fmt.Errorf("vpn config: wireguard conf empty")
		}
		fingerprint("wireguard conf", v.Conf)
	case "tailscale":
		if v.AuthKey == "" {
			return fmt.Errorf("vpn config: tailscale authkey empty")
		}
		fingerprint("tailscale authkey", v.AuthKey)
	default:
		return fmt.Errorf("vpn config: unknown type %q", v.Type)
	}
	if err := writeFileAtomic(vpnPath, payload, 0o600); err != nil {
		return err
	}
	return startVPN()
}

func startVPN() error {
	v, err := loadVPN()
	if err != nil {
		return fmt.Errorf("no vpn config stored: %w", err)
	}
	// Kill switch must be in place before the VPN comes up (§F4).
	if err := applyKillSwitch(); err != nil {
		log.Printf("kill switch re-apply before vpn start failed: %v", err)
	}
	store.set("vpn_starting", "")
	switch v.Type {
	case "wireguard":
		if err := writeFileAtomic(wgConfigPath, []byte(v.Conf), 0o600); err != nil {
			return err
		}
		out, err := exec.Command("systemctl", "start", "wg-quick@wg-hsl.service").CombinedOutput()
		if err != nil {
			store.set("idle", "vpn_failed")
			return fmt.Errorf("wg-quick@wg-hsl start: %v: %s", err, strings.TrimSpace(string(out)))
		}
		store.update(func(s *State) { s.VPN = true })
	case "tailscale":
		args := []string{"up", "--authkey", v.AuthKey}
		if v.ExitNode != "" {
			args = append(args, "--exit-node", v.ExitNode)
		}
		fingerprint("tailscale authkey", v.AuthKey)
		out, err := exec.Command("tailscale", args...).CombinedOutput()
		if err != nil {
			store.set("idle", "vpn_failed")
			// Never include tailscale output verbatim if it might echo the key.
			_ = out
			return fmt.Errorf("tailscale up failed: %v", err)
		}
		store.update(func(s *State) { s.VPN = true })
	}
	log.Printf("vpn up type=%s", v.Type)
	return nil
}

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
	store.update(func(s *State) { s.VPN = false })
	store.set("idle", "")
	return nil
}

// applyKillSwitch loads the nftables `hsl` table: forward from usb0 /
// wlan0-AP only via the VPN interface, default drop. Applied at startup
// before VPN, and never removed (§F4).
func applyKillSwitch() error {
	if _, err := os.Stat(nftFile); err == nil {
		out, err := exec.Command("nft", "-f", nftFile).CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft -f %s: %v: %s", nftFile, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// Embedded fallback identical to firmware/configs/nftables-hsl.nft.
	rules := "table inet hsl {\n" +
		" chain forward {\n" +
		"  type filter hook forward priority 0; policy drop;\n" +
		"  iifname \"usb0\" oifname \"wg-hsl\" accept\n" +
		"  iifname \"usb0\" oifname \"tailscale0\" accept\n" +
		"  iifname \"wlan0\" oifname \"wg-hsl\" accept\n" +
		"  iifname \"wlan0\" oifname \"tailscale0\" accept\n" +
		"  ct state established,related accept\n" +
		" }\n" +
		" chain input {\n" +
		"  type filter hook input priority 0; policy accept;\n" +
		" }\n" +
		"}\n"
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader("flush table inet hsl\n" + rules)
	// flush of a nonexistent table errors; load the table unconditionally instead.
	cmd2 := exec.Command("nft", "-f", "-")
	cmd2.Stdin = strings.NewReader(rules)
	out, err := cmd2.CombinedOutput()
	_ = cmd
	if err != nil {
		// Table may already exist from a previous apply: flush + reload.
		reload := exec.Command("nft", "-f", "-")
		reload.Stdin = strings.NewReader("flush table inet hsl\n" + rules)
		if out2, err2 := reload.CombinedOutput(); err2 != nil {
			return fmt.Errorf("nft load: %v: %s / %s", err2, out, out2)
		}
	}
	return nil
}

// portalPass opens a temporary 10-minute forward exception so the USB host
// can complete a captive-portal login, then removes it (§F4).
func portalPass() {
	log.Printf("portal_pass: opening temporary 10-min forward exception")
	add := exec.Command("nft", "add", "rule", "inet", "hsl", "forward",
		"iifname", "usb0", "tcp", "dport", "{ 80, 443 }", "accept", "comment", "\"hsl-portal-pass\"")
	if out, err := add.CombinedOutput(); err != nil {
		log.Printf("portal_pass add failed: %v: %s", err, strings.TrimSpace(string(out)))
		return
	}
	go func() {
		time.Sleep(10 * time.Minute)
		removePortalPass()
		log.Printf("portal_pass: temporary exception expired and removed")
	}()
}

func removePortalPass() {
	out, err := exec.Command("nft", "-a", "list", "chain", "inet", "hsl", "forward").CombinedOutput()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "hsl-portal-pass") && strings.Contains(line, "handle") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "handle" && i+1 < len(fields) {
					_ = exec.Command("nft", "delete", "rule", "inet", "hsl", "forward", "handle", fields[i+1]).Run()
				}
			}
		}
	}
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

// checkCaptiveAndVPN runs after a successful join: captive check, then VPN.
func checkCaptiveAndVPN() {
	if checkCaptive() {
		store.set("captive_portal", "captive_portal")
		log.Printf("captive portal detected (non-204 from generate_204); kill switch stays up")
		return
	}
	if _, err := loadVPN(); err == nil {
		if err := startVPN(); err != nil {
			log.Printf("vpn start failed: %v", err)
			return
		}
	}
	store.set("online", "")
}
