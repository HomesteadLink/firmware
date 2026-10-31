package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// VpnConfigPayload is the §F4 VpnConfig JSON schema (≤4096 B reassembled).
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

// stageVpnConfig is the ONE staging rule for every VpnConfig write
// (GATT, config page, in-transaction or Device screen): validate →
// write candidate/vpn.conf atomically. The caller decides the commit
// point: outside a Wi-Fi transaction the stage commits immediately
// (rename to committed vpn.conf); inside a transaction the file
// stays candidate for the transaction's VPN phase (DL43/DL44).
// Staging NEVER raises the VPN and never sets a terminal state.
func stageVpnConfig(payload []byte) (*VpnConfigPayload, string) {
	v, code := validateVpnPayload(payload)
	if code != "" {
		return nil, code
	}
	if v.Type == "wireguard" {
		fingerprint("wireguard conf", v.Conf)
	} else {
		fingerprint("tailscale authkey", v.AuthKey)
	}
	if err := writeFileAtomic(vpnCandPath, payload, 0o600); err != nil {
		return nil, "vpn_config_invalid"
	}
	return v, ""
}

// commitStagedVpnNow commits a staged candidate immediately (the
// Device-screen / no-transaction path).
func commitStagedVpnNow() {
	commitStagedVPN()
	log.Printf("vpn config staged and committed (no raise — takes effect on vpn_start or the next join sequence)")
}

// wifiOnline reports whether Wi-Fi is joined with a lease — the
// precondition for any VPN raise that may publish `online` (F2).
func wifiOnline() bool {
	st := store.get()
	return st.SSID != "" && st.IP4 != ""
}

// verifyKillSwitch (§F4/§F8 item 10): the merged ruleset is installed
// at /etc/nftables.conf and loaded by nftables.service. provisiond
// loads NO table of its own — it only verifies that inet hsl_filter
// exists before any VPN raise, and refuses (fail closed) otherwise.
func verifyKillSwitch() error {
	out, err := exec.Command("nft", "list", "table", "inet", "hsl_filter").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft list table inet hsl_filter: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// raiseAndValidateVPN raises the given config and proves the tunnel
// before publishing `online` (§F4 commit checks): WireGuard =
// handshake within 30 s + default route via wg-hsl; Tailscale =
// BackendState=Running + netcheck UDP within 30 s, and when an exit
// node is set, `tailscale ping <exit_node>` must succeed. EVERY
// failure lands in state vpn_failed with the paired error — never
// idle (critique f2). Success is the only path to `online`.
func raiseAndValidateVPN(v *VpnConfigPayload) error {
	fail := func(code string, err error) error {
		store.set("vpn_failed", code)
		log.Printf("vpn raise/validation failed (%s): %v", code, err)
		return err
	}
	if !wifiOnline() {
		return fmt.Errorf("wifi not online; vpn raise deferred")
	}
	if err := verifyKillSwitch(); err != nil {
		return fail("vpn_failed", fmt.Errorf("kill switch not in place, refusing vpn raise: %w", err))
	}
	store.set("vpn_starting", "")
	switch v.Type {
	case "wireguard":
		if err := writeFileAtomic(wgConfigPath, []byte(v.Conf), 0o600); err != nil {
			return fail("vpn_failed", err)
		}
		out, err := exec.Command("systemctl", "start", "wg-quick@wg-hsl.service").CombinedOutput()
		if err != nil {
			return fail("vpn_failed", fmt.Errorf("wg-quick@wg-hsl start: %v: %s", err, strings.TrimSpace(string(out))))
		}
		if err := waitWGHandshake(30 * time.Second); err != nil {
			return fail("vpn_failed", err)
		}
		if !defaultRouteVia("wg-hsl") {
			return fail("vpn_failed", fmt.Errorf("no default route via wg-hsl after raise"))
		}
		setDNSUpstream(wgDNS(v.Conf))
	case "tailscale":
		// Auth key via a 0600 file (file: scheme), never argv (F19).
		keyFile := cfgDir + "/.ts-authkey"
		if err := writeFileAtomic(keyFile, []byte(v.AuthKey), 0o600); err != nil {
			return fail("vpn_failed", err)
		}
		defer os.Remove(keyFile)
		// --accept-dns=false (§F4): dnsmasq is the ONE DNS owner.
		args := []string{"up", "--authkey", "file:" + keyFile, "--accept-dns=false"}
		if v.ExitNode != "" {
			args = append(args, "--exit-node", v.ExitNode)
		}
		fingerprint("tailscale authkey", v.AuthKey)
		if out, err := exec.Command("tailscale", args...).CombinedOutput(); err != nil {
			return fail("vpn_failed", fmt.Errorf("tailscale up failed: %v: %s", err, strings.TrimSpace(string(out))))
		}
		if err := waitTailscaleRunning(30 * time.Second); err != nil {
			code := "vpn_failed"
			if tailscaleKeyExpired() {
				code = "authkey_expired"
			}
			if !ntpSynchronized() {
				// §F4 clock rule: name the clock in the journal when a
				// Tailscale failure coincides with an unsynced clock.
				log.Printf("tailscale validation failed while the clock is NOT NTPSynchronized — TLS/clock is a likely cause (board has no RTC)")
			}
			return fail(code, fmt.Errorf("tailscale validation: %v", err))
		}
		if v.ExitNode != "" {
			// Exit-node liveness (§F4): a Running backend with a dead
			// exit node is vpn_failed, not online.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			out, err := exec.CommandContext(ctx, "tailscale", "ping", v.ExitNode).CombinedOutput()
			cancel()
			if err != nil {
				return fail("vpn_failed", fmt.Errorf("tailscale ping exit node %s: %v: %s", v.ExitNode, err, strings.TrimSpace(string(out))))
			}
		}
		setDNSUpstream("100.100.100.100")
	}
	store.update(func(s *State) { s.VPN = true })
	store.set("online", "")
	log.Printf("vpn up and validated type=%s", v.Type)
	return nil
}

// raiseCommittedVPN raises the committed vpn.conf.
func raiseCommittedVPN() error {
	v, err := loadVPN()
	if err != nil {
		return fmt.Errorf("no vpn config stored: %w", err)
	}
	return raiseAndValidateVPN(v)
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

// stopTunnel tears the tunnel down and removes the dnsmasq upstream.
// It does NOT set Status: the resulting state is the caller's
// decision (Decision Log 45 table in control.go).
func stopTunnel() {
	v, err := loadVPN()
	if err == nil && v.Type == "tailscale" {
		_ = exec.Command("tailscale", "down").Run()
	} else {
		_ = exec.Command("systemctl", "stop", "wg-quick@wg-hsl.service").Run()
		if err == nil && v.Type == "tailscale" {
			_ = exec.Command("tailscale", "down").Run()
		}
	}
	setDNSUpstream("")
	store.update(func(s *State) { s.VPN = false })
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

// --- Internet check (§F4): tri-state, never conflated ---

const (
	netOK = iota
	netPortal
	netUnreachable
)

// internetCheck GETs generate_204. A non-204 HTTP RESPONSE means a
// portal; NO response at all (transport error) is internet_unreachable
// — it is never captive_portal (Decision Log 42).
func internetCheck() int {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://connectivitycheck.gstatic.com/generate_204")
	if err != nil {
		return netUnreachable
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == 204 {
		return netOK
	}
	return netPortal
}

func ntpSynchronized() bool {
	out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "yes"
}

// waitNTPSynchronized implements the §F4 clock rule: wait for
// systemd-timesyncd up to the given budget (≤10 s, inside the
// internet-check phase budget).
func waitNTPSynchronized(budget time.Duration) {
	if budget > 10*time.Second {
		budget = 10 * time.Second
	}
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if ntpSynchronized() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Printf("clock not NTPSynchronized within %s; proceeding with internet check", budget)
}

// --- Captive-portal pass (§F4: grant and re-check are TWO commands) ---

const (
	passConfPath = "/etc/dnsmasq.d/hsl-pass.conf"
	passLogPath  = "/run/homesteadlink/dnsmasq-pass.log"
)

var passMu sync.Mutex
var passActive bool
var passAdmitted = map[string]bool{}

func portalPassActive() bool {
	passMu.Lock()
	defer passMu.Unlock()
	return passActive
}

// chownPassLog hands the pass log to the dnsmasq user (§F4 step
// (2b): provisiond pre-creates dnsmasq-pass.log, owner dnsmasq,
// mode 0644). dnsmasq appends its query log as that user — a
// root-owned file silently kills the admission channel (N6).
func chownPassLog() {
	u, err := user.Lookup("dnsmasq")
	if err != nil {
		log.Printf("portal_pass: dnsmasq user lookup failed: %v (pass log stays root-owned)", err)
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return
	}
	if err := os.Chown(passLogPath, uid, gid); err != nil {
		log.Printf("portal_pass: chown %s to dnsmasq failed: %v", passLogPath, err)
	}
}

// portalPassGrant opens the 10-minute pass. Gate (caller-enforced
// and re-checked here): state captive_portal and no pass active.
// Steps (§F4): resolve the check host + redirect target through the
// uplink's DHCP DNS (uplink_dns in state.json) with one-shot queries
// that bypass dnsmasq; insert destination-scoped accepts into the
// portal_pass chain (usb0 only, tcp 80/443); run dnsmasq with the
// pass config (server=<uplink DNS> + log-queries) and admit every A
// record the USB client resolves during the pass within 1 s; flush
// everything at exactly 10 min.
func portalPassGrant() {
	passMu.Lock()
	if passActive {
		passMu.Unlock()
		log.Printf("portal_pass rejected: a pass is already active (busy)")
		store.update(func(s *State) { s.Error = "busy" })
		return
	}
	passActive = true
	passAdmitted = map[string]bool{}
	passMu.Unlock()

	dns := store.getUplinkDNS()
	ips := map[string]string{} // ip -> hostname (for the journal)
	resolve := func(host string) {
		for _, ip := range resolveViaUplink(host, dns) {
			ips[ip] = host
		}
	}
	checkHost := "connectivitycheck.gstatic.com"
	resolve(checkHost)
	// The portal redirect target (one no-redirect fetch; device-
	// originated traffic is allowed by the output chain pre-pass).
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if resp, err := client.Get("http://" + checkHost + "/generate_204"); err == nil {
		loc := resp.Header.Get("Location")
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if loc != "" {
			if h := hostOf(loc); h != "" {
				resolve(h)
				log.Printf("portal_pass: redirect target host %s", h)
			}
		}
	}
	for ip, host := range ips {
		admitPortalIP(ip, host)
	}

	// Pass DNS: dnsmasq gets the uplink upstream + query logging via
	// the pass-only config file; removed again at expiry.
	_ = os.MkdirAll("/run/homesteadlink", 0o755)
	_ = os.WriteFile(passLogPath, nil, 0o644)
	chownPassLog()
	if dns != "" {
		conf := "server=" + dns + "\nlog-queries\nlog-facility=" + passLogPath + "\n"
		if err := writeFileAtomic(passConfPath, []byte(conf), 0o644); err != nil {
			log.Printf("portal_pass: cannot write %s: %v", passConfPath, err)
		}
	} else {
		log.Printf("portal_pass: no uplink_dns captured — pass DNS upstream unavailable (grant continues with resolved IPs only)")
	}
	_ = exec.Command("systemctl", "restart", "dnsmasq.service").Run()

	expiry := time.Now().Add(10 * time.Minute)
	log.Printf("portal_pass: GRANTED — dst set %v via dns=%q, expires %s (exactly 10 min)", ips, dns, expiry.Format(time.RFC3339))
	go passAdmissionLoop(expiry)
	go func() {
		time.Sleep(10 * time.Minute)
		portalPassExpire()
	}()
}

// resolveViaUplink resolves host with one-shot DNS queries sent
// directly to the uplink DNS server (bypassing dnsmasq, which has no
// upstream until the pass config runs). Falls back to the system
// resolver when no uplink DNS is known.
func resolveViaUplink(host, dns string) []string {
	var ips []string
	if dns == "" {
		addrs, err := net.LookupIP(host)
		if err != nil {
			return nil
		}
		for _, a := range addrs {
			if a.To4() != nil {
				ips = append(ips, a.String())
			}
		}
		return ips
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dns, "53"))
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := r.LookupIP(ctx, "ip4", host)
	if err != nil {
		log.Printf("portal_pass: resolve %s via uplink dns %s failed: %v", host, dns, err)
		return nil
	}
	for _, a := range addrs {
		if a.To4() != nil {
			ips = append(ips, a.String())
		}
	}
	return ips
}

// admitPortalIP inserts ONE destination-scoped accept into the
// portal_pass chain (the chain's only writer is this file) and
// journals the admission with its hostname (§F4 step 2b).
func admitPortalIP(ip, host string) {
	passMu.Lock()
	if passAdmitted[ip] {
		passMu.Unlock()
		return
	}
	passAdmitted[ip] = true
	passMu.Unlock()
	snippet := fmt.Sprintf("add rule inet hsl_filter portal_pass iifname \"usb0\" ip daddr %s tcp dport { 80, 443 } accept comment \"hsl-portal-pass\"\n", ip)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(snippet)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("portal_pass: nft add for %s (%s) failed: %v: %s", ip, host, err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("portal_pass: admitted dst=%s host=%s (usb0, tcp 80/443)", ip, host)
}

// passAdmissionLoop tails the dnsmasq pass log (100 ms poll) and
// admits every A record the USB client resolves through the pass
// upstream — the sign-in flow's auth/CDN hosts are unknown at grant
// time, so the log is the admission channel (§F4 step 2b).
func passAdmissionLoop(expiry time.Time) {
	var offset int64
	for time.Now().Before(expiry) && portalPassActive() {
		time.Sleep(100 * time.Millisecond)
		fi, err := os.Stat(passLogPath)
		if err != nil || fi.Size() < offset {
			continue
		}
		if fi.Size() == offset {
			continue
		}
		f, err := os.Open(passLogPath)
		if err != nil {
			continue
		}
		_, _ = f.Seek(offset, io.SeekStart)
		buf := make([]byte, fi.Size()-offset)
		n, _ := f.Read(buf)
		f.Close()
		offset += int64(n)
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			// dnsmasq log-queries reply line: "reply <host> is <ip>"
			fields := strings.Fields(line)
			for i, fld := range fields {
				if fld == "reply" && i+3 < len(fields) && fields[i+2] == "is" {
					host, ipStr := fields[i+1], fields[i+3]
					if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
						admitPortalIP(ipStr, host)
					}
				}
			}
		}
	}
}

// portalPassExpire removes the whole exception at exactly 10 min:
// flush the chain, remove the pass config, truncate the log, restart
// dnsmasq (§F4 pass scope).
func portalPassExpire() {
	passMu.Lock()
	if !passActive {
		passMu.Unlock()
		return
	}
	passActive = false
	passMu.Unlock()
	_ = exec.Command("nft", "flush", "chain", "inet", "hsl_filter", "portal_pass").Run()
	_ = os.Remove(passConfPath)
	_ = os.WriteFile(passLogPath, nil, 0o644)
	chownPassLog()
	_ = exec.Command("systemctl", "restart", "dnsmasq.service").Run()
	log.Printf("portal_pass: expired — chain flushed, pass DNS removed, dnsmasq restarted")
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

// portalRecheck is the §F4 re-check command: it re-runs the internet
// check whether or not a pass is active — portal_pass never does
// this. On 204 the paused party (transaction or boot rejoin)
// continues; on transport error the paused transaction rolls back
// with internet_unreachable (DL42) and a paused rejoin drops to the
// 60 s re-check loop.
func portalRecheck() {
	switch internetCheck() {
	case netOK:
		switch portalPauseKind() {
		case "tx":
			// Take the channel and clear the pause atomically: a
			// second recheck must not close it again.
			portalPause.Lock()
			ch := portalPause.resumeCh
			portalPause.kind = ""
			portalPause.resumeCh = nil
			portalPause.abortCh = nil
			portalPause.Unlock()
			if ch != nil {
				close(ch)
			}
		case "rejoin":
			clearPortalPause()
			log.Printf("portal_recheck: 204 — boot rejoin continues at the VPN step")
			go vpnStep()
		default:
			log.Printf("portal_recheck: 204 — no paused party; refreshing post-join flow")
			if hasVPNConfig() {
				_ = raiseCommittedVPN()
			} else if wifiOnline() {
				store.set("online_no_vpn", "")
			}
		}
	case netPortal:
		log.Printf("portal_recheck: still a portal (non-204) — staying captive_portal")
		if store.get().State != "captive_portal" {
			store.set("captive_portal", "captive_portal")
		}
	case netUnreachable:
		switch portalPauseKind() {
		case "tx":
			portalPause.Lock()
			ch := portalPause.abortCh
			portalPause.kind = ""
			portalPause.resumeCh = nil
			portalPause.abortCh = nil
			portalPause.Unlock()
			if ch != nil {
				close(ch)
			}
		case "rejoin":
			clearPortalPause()
			store.set("idle", "internet_unreachable")
			go rejoinRecheckLoop()
		default:
			store.set("idle", "internet_unreachable")
		}
		log.Printf("portal_recheck: transport error — internet_unreachable (never captive_portal)")
	}
}
