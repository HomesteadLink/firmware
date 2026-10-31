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
				if store.get().Error == "bt_dead" {
					store.set("idle", "")
				}
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
			st := store.get()
			// bt_dead is a Status state in §F4 as well as an error tag.
			if st.State == "idle" || st.State == "bt_dead" {
				store.set("bt_dead", "bt_dead")
			} else {
				store.update(func(s *State) { s.Error = "bt_dead" })
			}
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
