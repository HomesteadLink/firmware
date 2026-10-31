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
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

func knownControlCmd(cmd string) bool {
	switch cmd {
	case "reboot", "factory_reset", "close_window", "vpn_stop", "vpn_start",
		"unbond", "portal_pass", "diagnostics":
		return true
	}
	return false
}

// handleControl executes §F4 Control commands. Runs in its own
// goroutine from the write path; unknown commands never reach here
// (rejected synchronously in the GATT write handler, F16).
func handleControl(cmd string, options map[string]dbus.Variant, s *gattServer) {
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
		log.Printf("control: vpn_stop")
		_ = stopVPN()
	case "vpn_start":
		log.Printf("control: vpn_start")
		// F2: online only via the §F4 raise+validation path.
		if err := raiseAndValidateVPN(); err != nil {
			log.Printf("vpn_start: %v", err)
		}
	case "unbond":
		if !isOwner(options) {
			log.Printf("control: unbond rejected — not the owner")
			return
		}
		log.Printf("control: unbond (owner) — bond removed, peer disconnected")
		unbondAll()
		if s != nil {
			s.disconnectNonOwners()
			// The owner peer itself is disconnected after unbond
			// (gatt.md): drop every remaining central too.
			s.disconnectAllCentrals()
		}
	case "portal_pass":
		// R3-1: grant and recheck are SEPARATE operations. With no
		// active grant, portal_pass only opens the exception. While
		// a grant is active, portal_pass is the app's explicit
		// recheck trigger (§F4: "sends portal_pass again to re-run
		// the check") — it does not extend or re-open the grant.
		if portalGrantActive() {
			log.Printf("control: portal_pass — recheck (grant already active)")
			checkCaptiveAndVPN()
		} else {
			log.Printf("control: portal_pass — grant only (no recheck side effect)")
			portalPass()
		}
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
// candidate wifi.conf/vpn.conf, state.json. Surviving = identity.json
// + device-secret — the setup code and printed label stay valid.
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
	clearPairingFailures()
	store.mu.Lock()
	store.st = State{State: "factory_reset"}
	store.txPhase = ""
	store.mu.Unlock()
	store.persist()
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
// 24 h of hsl journal, state.json (secrets are never in it by
// construction), `nft list ruleset` and `tailscale status`.
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

var _ = strings.TrimSpace // reserved for future redaction passes
