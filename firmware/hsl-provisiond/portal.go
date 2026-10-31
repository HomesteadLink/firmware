package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"
)

// apFallbackServer (§F5): while in AP / provisioning mode (no committed
// Wi-Fi config), serve a minimal HTTP config page on 172.30.0.1:8080 that
// posts to the same apply-transaction as the BLE WifiConfig path.
// The usb0/AP address may not exist at daemon start, so bind retries.
func apFallbackServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var p WifiConfigPayload
			// Accept both form posts (browser page) and JSON.
			if r.Header.Get("Content-Type") == "application/json" {
				_ = json.NewDecoder(r.Body).Decode(&p)
			} else {
				_ = r.ParseForm()
				p.SSID = r.FormValue("ssid")
				p.PSK = r.FormValue("psk")
				p.Country = r.FormValue("country")
				p.Hidden = r.FormValue("hidden") == "on"
			}
			if p.SSID == "" {
				http.Error(w, "ssid required", http.StatusBadRequest)
				return
			}
			fingerprint("wifi psk (ap page)", p.PSK)
			payload, _ := json.Marshal(p)
			go func() {
				if err := applyWifiTransaction(payload); err != nil {
					log.Printf("ap page wifi apply: %v", err)
					return
				}
				checkCaptiveAndVPN()
			}()
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body><h1>Applying…</h1><p>Joining the network. Watch the device status.</p></body></html>"))
			return
		}
		st := store.get()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>HomeSteadyLink setup</title></head><body>
<h1>HomeSteadyLink setup</h1>
<p>State: ` + st.State + `</p>
<form method="post">
<label>Wi-Fi name (SSID)<br><input name="ssid" required></label><br><br>
<label>Wi-Fi password<br><input name="psk" type="password"></label><br><br>
<label>Country (2-letter)<br><input name="country" size="2"></label><br><br>
<label><input type="checkbox" name="hidden"> Hidden network</label><br><br>
<button type="submit">Join</button>
</form></body></html>`))
	})
	srv := &http.Server{Addr: "172.30.0.1:8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	for {
		if hasWifiConfig() {
			time.Sleep(10 * time.Second)
			continue
		}
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			// usb0 / AP address not up yet.
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("AP fallback config page listening on %s", srv.Addr)
		_ = srv.Serve(ln) // returns when the listener dies; loop re-evaluates
		time.Sleep(2 * time.Second)
	}
}
