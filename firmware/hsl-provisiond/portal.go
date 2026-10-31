package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// apFallbackServer (§F5, F7/F13): the config page binds the canonical
// addresses — 192.168.64.1:8080 on usb0 and 192.168.65.1:8080 in AP
// mode — serves only while unconfigured / in AP mode, and EVERY POST
// requires the setup-code token (§F5; F7.7 tests the rejection).
func tokenOK(r *http.Request, formToken string) bool {
	if identity.SetupCode == "" {
		return false
	}
	if r.Header.Get("X-Setup-Code") == identity.SetupCode {
		return true
	}
	if r.URL.Query().Get("token") == identity.SetupCode {
		return true
	}
	return formToken == identity.SetupCode
}

func apFallbackServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(r, "") {
			http.Error(w, "setup-code token required", http.StatusForbidden)
			return
		}
		if _, err := os.Stat(diagPath); err != nil {
			if err := buildDiagnostics(); err != nil {
				http.Error(w, "diagnostics unavailable", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/gzip")
		http.ServeFile(w, r, diagPath)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var p WifiConfigPayload
			token := ""
			if r.Header.Get("Content-Type") == "application/json" {
				var body struct {
					WifiConfigPayload
					Token string `json:"token"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				p, token = body.WifiConfigPayload, body.Token
			} else {
				_ = r.ParseForm()
				p.SSID = r.FormValue("ssid")
				p.PSK = r.FormValue("psk")
				p.Country = r.FormValue("country")
				p.Hidden = r.FormValue("hidden") == "on"
				token = r.FormValue("token")
			}
			if !tokenOK(r, token) {
				http.Error(w, "setup-code token required", http.StatusForbidden)
				return
			}
			if p.SSID == "" {
				http.Error(w, "ssid required", http.StatusBadRequest)
				return
			}
			fingerprint("wifi psk (config page)", p.PSK)
			payload, _ := json.Marshal(p)
			go func() {
				if err := applyWifiTransaction(payload); err != nil {
					log.Printf("config page wifi apply: %v", err)
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
<p>Setup code (also on the device label): ` + identity.SetupCode + `</p>
<form method="post">
<label>Setup-code token<br><input name="token" required></label><br><br>
<label>Wi-Fi name (SSID)<br><input name="ssid" required></label><br><br>
<label>Wi-Fi password<br><input name="psk" type="password"></label><br><br>
<label>Country (2-letter)<br><input name="country" size="2"></label><br><br>
<label><input type="checkbox" name="hidden"> Hidden network</label><br><br>
<button type="submit">Join</button>
</form></body></html>`))
	})

	addrs := []string{"192.168.64.1:8080", "192.168.65.1:8080"}
	serving := map[string]bool{}
	for {
		if hasWifiConfig() {
			time.Sleep(10 * time.Second)
			continue
		}
		for _, addr := range addrs {
			if serving[addr] {
				continue
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				continue // interface address not up yet
			}
			serving[addr] = true
			log.Printf("config page listening on %s (token-gated)", addr)
			srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			go func(a string, l net.Listener) {
				_ = srv.Serve(l)
				serving[a] = false
			}(addr, ln)
		}
		time.Sleep(5 * time.Second)
	}
}
