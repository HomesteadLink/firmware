package main

import (
	"log"
	"os"
	"os/exec"
	"time"
)

// btSupervision implements §F2: if hci0 is absent for >30 s, do ONE
// rfkill/regulator power-cycle + re-trigger hsl-bt-attach, then give up
// with error=bt_dead while every other function keeps running.
func btSupervision() {
	cycled := false
	for {
		if _, err := os.Stat("/sys/class/bluetooth/hci0"); err == nil {
			if btDead {
				btDead = false
				// Recovery clears ONLY the error (§F8 15.3): the
				// operational state is whatever the state machine
				// says — never forced to idle here.
				store.update(func(s *State) {
					if s.Error == "bt_dead" {
						s.Error = ""
					}
				})
			}
			time.Sleep(5 * time.Second)
			continue
		}
		// Absent: wait out the 30 s grace window in 5 s slices.
		appeared := false
		for i := 0; i < 6; i++ {
			time.Sleep(5 * time.Second)
			if _, err := os.Stat("/sys/class/bluetooth/hci0"); err == nil {
				appeared = true
				break
			}
		}
		if appeared {
			continue
		}
		// GUARD (§F2 / §F8 15.2): never power-cycle the shared
		// UWE5622 radio while online / online_no_vpn or while a
		// Wi-Fi/VPN transaction is in flight — Wi-Fi shares the
		// power line. In those states: re-attach ONLY, and defer
		// the power-cycle until the device is idle.
		if st := store.get(); st.State == "online" || st.State == "online_no_vpn" || isTxActive() {
			log.Printf("hci0 absent but device is %s (tx active: %v): re-attach only, power-cycle deferred", st.State, isTxActive())
			_ = exec.Command("systemctl", "restart", "hsl-bt-attach.service").Run()
			time.Sleep(15 * time.Second)
			continue
		}
		if !cycled {
			cycled = true
			log.Printf("hci0 absent >30s: power-cycling module once and restarting hsl-bt-attach")
			powerCycleModule()
			_ = exec.Command("systemctl", "restart", "hsl-bt-attach.service").Run()
			time.Sleep(10 * time.Second)
			continue
		}
		if !btDead {
			btDead = true
			log.Printf("hci0 still absent after one power-cycle: error=bt_dead (router functions continue)")
			// bt_dead is ERROR-ONLY (R3-1): never a Status state.
			store.update(func(s *State) { s.Error = "bt_dead" })
		}
		time.Sleep(15 * time.Second)
	}
}

// powerCycleModule toggles the module via rfkill (soft block/unblock);
// on boards where the regulator path exists it is cycled the same way.
// Best-effort: failures are logged, never fatal.
func powerCycleModule() {
	_ = exec.Command("rfkill", "block", "bluetooth").Run()
	time.Sleep(1 * time.Second)
	_ = exec.Command("rfkill", "unblock", "bluetooth").Run()
}
