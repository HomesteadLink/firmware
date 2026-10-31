package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/godbus/dbus/v5"
)

// handleControl executes §F4 Control commands (plus the task-added
// unbond and portal_pass). Runs in its own goroutine from the write path.
func handleControl(cmd string, options map[string]dbus.Variant, s *gattServer) {
	switch cmd {
	case "reboot":
		log.Printf("control: reboot")
		_ = exec.Command("systemctl", "reboot").Run()
	case "factory_reset":
		log.Printf("control: factory_reset — wiping %s config and unbonding", cfgDir)
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
		if err := startVPN(); err != nil {
			log.Printf("vpn_start: %v", err)
		} else {
			store.set("online", "")
		}
	case "unbond":
		// Owner only (§F4).
		if !isOwner(options) {
			log.Printf("control: unbond rejected — not the owner")
			return
		}
		log.Printf("control: unbond (owner)")
		unbondAll()
	case "portal_pass":
		log.Printf("control: portal_pass")
		// §F4: open the temporary 10-min forward exception so the host can
		// sign in; contract: also re-run the internet check — if the portal
		// is cleared the device goes online/VPN-up, otherwise the state
		// stays captive_portal and the exception stays for the sign-in.
		portalPass()
		checkCaptiveAndVPN()
	default:
		log.Printf("control: unknown cmd %q", cmd)
	}
}

// factoryReset wipes /etc/homesteadlink config + bonds, keeping identity.
func factoryReset() {
	entries, _ := filepath.Glob(cfgDir + "/*")
	for _, e := range entries {
		if filepath.Base(e) == "identity.json" {
			continue
		}
		_ = os.Remove(e)
	}
	unbondAll()
	_ = exec.Command("systemctl", "stop", "wg-quick@wg-hsl.service").Run()
	store.st = State{State: "factory_reset"}
	persistState(store.st)
}

// unbondAll removes all BlueZ pairings for the adapter (best effort via
// bluetoothctl) and clears the recorded owner.
func unbondAll() {
	_ = os.Remove(ownerPath)
	out, err := exec.Command("bluetoothctl", "devices", "Paired").CombinedOutput()
	if err == nil {
		// Lines: "Device AA:BB:.. Name"
		for _, line := range splitLines(string(out)) {
			fields := splitFields(line)
			if len(fields) >= 2 && fields[0] == "Device" {
				_ = exec.Command("bluetoothctl", "remove", fields[1]).Run()
			}
		}
	}
}
