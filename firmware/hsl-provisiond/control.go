package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/godbus/dbus/v5"
)

func knownControlCmd(cmd string) bool {
	switch cmd {
	case "reboot", "factory_reset", "close_window", "vpn_stop", "vpn_start",
		"unbond", "portal_pass", "portal_recheck", "diagnostics":
		return true
	}
	return false
}

// handleControl executes §F4 Control commands. Runs in its own
// goroutine from the write path; unknown commands never reach here
// (rejected synchronously in the GATT write handler, F16). EVERY
// command is owner-checked here as well as on the write path (§F8
// item 16.4 — no reliance on a single gate).
func handleControl(cmd string, options map[string]dbus.Variant, s *gattServer) {
	if !isOwner(options) {
		log.Printf("control: %s rejected — not the owner", cmd)
		return
	}
	switch cmd {
	case "reboot":
		log.Printf("control: reboot")
		_ = exec.Command("systemctl", "reboot").Run()
	case "factory_reset":
		log.Printf("control: factory_reset — wiping config and bonds (identity + device-secret survive)")
		store.set("factory_reset", "")
		factoryReset()
		time.Sleep(500 * time.Millisecond)
		_ = exec.Command("systemctl", "reboot").Run()
	case "close_window":
		log.Printf("control: close_window")
		if s != nil {
			s.CloseWindow()
		}
	case "vpn_stop":
		// Decision Log 45: online → online_no_vpn; vpn_failed →
		// online_no_vpn (committed-but-down vpn.conf stays stored);
		// no VPN up → no-op success, state unchanged.
		st := store.get()
		switch st.State {
		case "online", "vpn_failed":
			log.Printf("control: vpn_stop from %s → online_no_vpn", st.State)
			stopTunnel()
			store.set("online_no_vpn", "")
		default:
			log.Printf("control: vpn_stop no-op (state %s, no VPN up)", st.State)
		}
	case "vpn_start":
		// Decision Log 45: already online → no-op; no committed
		// vpn.conf → rejected error=vpn_config_invalid, state
		// unchanged; Wi-Fi + internet not up → rejected error=busy,
		// state unchanged; from online_no_vpn / vpn_failed →
		// vpn_starting → online / vpn_failed via the commit check.
		st := store.get()
		switch {
		case st.State == "online":
			log.Printf("control: vpn_start no-op (already online)")
		case !hasVPNConfig():
			log.Printf("control: vpn_start rejected — no committed vpn.conf (vpn_config_invalid)")
			store.update(func(s *State) { s.Error = "vpn_config_invalid" })
		case st.State != "online_no_vpn" && st.State != "vpn_failed":
			log.Printf("control: vpn_start rejected — state %s has no committed Wi-Fi + internet up (busy)", st.State)
			store.update(func(s *State) { s.Error = "busy" })
		default:
			log.Printf("control: vpn_start from %s", st.State)
			if err := raiseCommittedVPN(); err != nil {
				log.Printf("vpn_start: %v (state vpn_failed set by the raise path)", err)
			}
		}
	case "unbond":
		log.Printf("control: unbond (owner) — bond removed, peer disconnected")
		unbondAll()
		if s != nil {
			s.disconnectNonOwners()
			// The owner peer itself is disconnected after unbond
			// (gatt.md): drop every remaining central too.
			s.disconnectAllCentrals()
		}
	case "portal_pass":
		// §F4: portal_pass GRANTS only — it never re-checks. Valid
		// only in state captive_portal with no pass active; while a
		// pass is active it is rejected with error=busy.
		if store.get().State != "captive_portal" {
			log.Printf("control: portal_pass rejected — state is %s, not captive_portal (no grant)", store.get().State)
			return
		}
		if portalPassActive() {
			log.Printf("control: portal_pass rejected — pass already active (busy, no extension, no re-grant)")
			store.update(func(sx *State) { sx.Error = "busy" })
			return
		}
		log.Printf("control: portal_pass — granting the 10-minute pass (no recheck)")
		portalPassGrant()
	case "portal_recheck":
		// §F4: portal_recheck is the ONLY re-check command.
		log.Printf("control: portal_recheck — re-running the internet check")
		portalRecheck()
	case "diagnostics":
		log.Printf("control: diagnostics — building %s", diagPath)
		if err := buildDiagnostics(); err != nil {
			log.Printf("diagnostics build failed: %v", err)
		}
	}
}

func (s *gattServer) disconnectAllCentrals() {
	if s.conn == nil {
		return
	}
	om := s.conn.Object("org.bluez", "/")
	var objects map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	call := om.Call("org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0)
	if call.Err != nil || call.Store(&objects) != nil {
		return
	}
	for path, ifaces := range objects {
		dev, ok := ifaces["org.bluez.Device1"]
		if !ok {
			continue
		}
		if connected, _ := dev["Connected"].Value().(bool); connected {
			_ = s.conn.Object("org.bluez", path).Call("org.bluez.Device1.Disconnect", 0)
		}
	}
}

// factoryReset (§F4 exact scope): wiped = BlueZ bonds, committed +
// candidate wifi.conf and vpn.conf, state.json. Surviving =
// identity.json + device-secret — the setup code, console password
// and AP passphrase are derived from those two, so the printed label
// stays valid (critique R3-1: the secret is NEVER deleted).
func factoryReset() {
	for _, p := range []string{wifiPath, vpnPath, wgConfigPath, ownerJSONPath} {
		_ = os.Remove(p)
	}
	_ = os.RemoveAll(candidateDir)
	_ = os.MkdirAll(candidateDir, 0o755)
	// Bonds: remove via bluetoothctl AND clear the BlueZ store.
	unbondAll()
	if entries, err := os.ReadDir(bluetoothStateDir); err == nil {
		for _, e := range entries {
			_ = os.RemoveAll(filepath.Join(bluetoothStateDir, e.Name()))
		}
	}
	clearPortalPause()
	clearPairingFailures()
	store.mu.Lock()
	store.st = State{State: "factory_reset"}
	store.txPhase = ""
	store.uplinkDNS = ""
	store.mu.Unlock()
	store.persist() // state.json restarts as a fresh counters-only doc
}

// unbondAll removes all BlueZ pairings for the adapter and clears the
// recorded owner identity.
func unbondAll() {
	_ = os.Remove(ownerJSONPath)
	out, err := exec.Command("bluetoothctl", "devices", "Paired").CombinedOutput()
	if err == nil {
		for _, line := range splitLines(string(out)) {
			fields := splitFields(line)
			if len(fields) >= 2 && fields[0] == "Device" {
				_ = exec.Command("bluetoothctl", "remove", fields[1]).Run()
			}
		}
	}
}

// buildDiagnostics (§F4): /etc/homesteadlink/diag.tar.gz with the last
// 24 h of hsl journal, state.json (config + counters only — no
// secrets by construction), `nft list ruleset` and `tailscale status`.
func buildDiagnostics() error {
	files := map[string][]byte{}
	if out, err := exec.Command("journalctl", "-u", "hsl-provisiond", "-u", "hsl-bt-attach", "-u", "hsl-firstboot",
		"--since", "-24h", "--no-pager").CombinedOutput(); err == nil {
		files["journal-24h.log"] = out
	}
	if b, err := os.ReadFile(statePath); err == nil {
		files["state.json"] = b
	}
	if out, err := exec.Command("nft", "list", "ruleset").CombinedOutput(); err == nil {
		files["nft-ruleset.txt"] = out
	}
	if out, err := exec.Command("tailscale", "status").CombinedOutput(); err == nil {
		files["tailscale-status.txt"] = out
	}
	if b, err := json.Marshal(map[string]string{
		"model": modelName, "serial": identity.Serial, "fw": fwVersion,
		"state": store.get().State,
	}); err == nil {
		files["device.json"] = b
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return writeFileAtomic(diagPath, buf.Bytes(), 0o600)
}
