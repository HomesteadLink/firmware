package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Config page (§F5 contract — ONE page, both addresses):
//   GET /            HTML form + current state
//   GET /status      the Status JSON (same shape as GATT Status)
//   POST /wifi       JSON = WifiConfig schema → the §F4 transaction
//   POST /vpn        JSON = VpnConfig schema → the one staging rule
//   GET /diagnostics the diag.tar.gz (Control diagnostics bundle)
//
// Token = the console password (§F1), transported in the
// X-HSL-Token header, required on EVERY endpoint including GET /:
// an unauthenticated request gets HTTP 403 with the plain-text body
// "X-HSL-Token required" — no form, no state, no data. Brute-force
// control: 5 failed token attempts from one source IP lock that IP
// out for 15 min (journal-logged); a successful auth resets the
// counter. Availability: binds 192.168.64.1:8080 whenever provisiond
// runs (NOT pre-setup-only) and 192.168.65.1:8080 while AP mode is
// active. The token travels ONLY in the X-HSL-Token header (§F5 +
// §F8 item 11) — never as a form or JSON field (N9); the served
// form submits via a script that sets the header.

type tokenGate struct {
	mu       sync.Mutex
	failures map[string]int
	locked   map[string]time.Time
}

var pageGate = &tokenGate{failures: map[string]int{}, locked: map[string]time.Time{}}

func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// checkToken validates the request's token. A failure is counted;
// the 5th failure from one IP locks it for 15 min.
func (g *tokenGate) checkToken(r *http.Request) bool {
	if identity.ConsolePass == "" {
		return false
	}
	ip := sourceIP(r)
	g.mu.Lock()
	if until, ok := g.locked[ip]; ok && time.Now().Before(until) {
		g.mu.Unlock()
		return false
	}
	g.mu.Unlock()

	ok := r.Header.Get("X-HSL-Token") == identity.ConsolePass // header ONLY (§F8 item 11)

	g.mu.Lock()
	defer g.mu.Unlock()
	if ok {
		delete(g.failures, ip)
		return true
	}
	g.failures[ip]++
	if g.failures[ip] >= 5 {
		g.locked[ip] = time.Now().Add(15 * time.Minute)
		delete(g.failures, ip)
		log.Printf("config page: source IP %s locked out for 15 min after 5 failed token attempts", ip)
	}
	return false
}

func (g *tokenGate) require(w http.ResponseWriter, r *http.Request) bool {
	if g.checkToken(r) {
		return true
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("X-HSL-Token required"))
	return false
}

func apFallbackServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if !pageGate.require(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(store.json())
	})

	mux.HandleFunc("/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		if !pageGate.require(w, r) {
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

	mux.HandleFunc("/wifi", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var p WifiConfigPayload
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			_ = json.NewDecoder(r.Body).Decode(&p)
		} else {
			_ = r.ParseForm()
			p.SSID = r.FormValue("ssid")
			p.PSK = r.FormValue("psk")
			p.Country = r.FormValue("country")
			p.Hidden = r.FormValue("hidden") == "on"
		}
		if !pageGate.require(w, r) {
			return
		}
		payload, _ := json.Marshal(p)
		parsed, code := validateWifiPayload(payload)
		if code != "" {
			store.update(func(s *State) { s.Error = code })
			http.Error(w, "wifi config invalid: "+code, http.StatusBadRequest)
			return
		}
		if securityClass(*parsed) == "eap" {
			store.set("idle", "unsupported_eap")
			http.Error(w, "802.1X/EAP not supported in v1", http.StatusBadRequest)
			return
		}
		fingerprint("wifi psk (config page)", parsed.PSK)
		go runWifiTransaction(parsed)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("applying — watch /status"))
	})

	mux.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var body VpnConfigPayload
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if !pageGate.require(w, r) {
			return
		}
		payload, _ := json.Marshal(body)
		if _, code := stageVpnConfig(payload); code != "" {
			store.update(func(s *State) { s.Error = code })
			http.Error(w, "vpn config invalid: "+code, http.StatusBadRequest)
			return
		}
		if isTxActive() {
			log.Printf("config page: VpnConfig staged in candidate/ for the running transaction")
		} else {
			commitStagedVpnNow()
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("vpn config stored"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if !pageGate.require(w, r) {
			return
		}
		st := store.get()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>HomeSteadyLink setup</title></head><body>
<h1>HomeSteadyLink setup</h1>
<p>State: ` + st.State + `</p>
<form id="f">
<label>Console-password token<br><input id="token" type="password" required></label><br><br>
<label>Wi-Fi name (SSID)<br><input id="ssid" required></label><br><br>
<label>Wi-Fi password<br><input id="psk" type="password"></label><br><br>
<label>Country (2-letter)<br><input id="country" size="2"></label><br><br>
<label><input id="hidden" type="checkbox"> Hidden network</label><br><br>
<button type="submit">Join</button>
</form>
<p id="msg"></p>
<script>
// The token travels ONLY in the X-HSL-Token header (§F8 item 11),
// so the form submits via fetch with the header set — never as a
// form field.
document.getElementById('f').addEventListener('submit', function(e){
  e.preventDefault();
  fetch('/wifi', {method: 'POST',
    headers: {'X-HSL-Token': document.getElementById('token').value, 'Content-Type': 'application/json'},
    body: JSON.stringify({ssid: document.getElementById('ssid').value,
      psk: document.getElementById('psk').value,
      country: document.getElementById('country').value,
      hidden: document.getElementById('hidden').checked})
  }).then(function(r){ return r.text(); }).then(function(t){ document.getElementById('msg').textContent = t; });
});
</script></body></html>`))
	})

	// Availability (§F5): 192.168.64.1 whenever the daemon runs;
	// 192.168.65.1 binds as soon as AP mode assigns the address.
	addrs := []string{"192.168.64.1:8080", "192.168.65.1:8080"}
	serving := map[string]bool{}
	for {
		for _, addr := range addrs {
			if serving[addr] {
				continue
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				continue // interface address not up (yet / anymore)
			}
			serving[addr] = true
			log.Printf("config page listening on %s (console-password token on every endpoint)", addr)
			srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			go func(a string, l net.Listener) {
				_ = srv.Serve(l)
				serving[a] = false
			}(addr, ln)
		}
		time.Sleep(5 * time.Second)
	}
}
