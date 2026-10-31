package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// Fixed GATT UUIDs (§F4 / spec/gatt.md — do not change).
const (
	uuidService    = "7f3a0000-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	uuidDeviceInfo = "7f3a0001-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	uuidWifiScan   = "7f3a0002-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	uuidWifiConfig = "7f3a0003-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	uuidVpnConfig  = "7f3a0004-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	uuidStatus     = "7f3a0005-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	uuidControl    = "7f3a0006-1c2d-4e5f-8a9b-0c1d2e3f4a5b"

	appPath     = dbus.ObjectPath("/com/homesteadlink/gatt")
	svcPath     = dbus.ObjectPath("/com/homesteadlink/gatt/service0")
	advPath     = dbus.ObjectPath("/com/homesteadlink/adv0")
	agentPath   = dbus.ObjectPath("/com/homesteadlink/agent")
	adapterPath = dbus.ObjectPath("/org/bluez/hci0")
)

func charPath(i int) dbus.ObjectPath {
	return dbus.ObjectPath(fmt.Sprintf("/com/homesteadlink/gatt/service0/char%d", i))
}

// --- generic org.freedesktop.DBus.Properties implementation ---

type props struct {
	mu sync.Mutex
	m  map[string]map[string]dbus.Variant // iface -> prop -> value
}

func (p *props) Get(iface, name string) (dbus.Variant, *dbus.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m, ok := p.m[iface]; ok {
		if v, ok := m[name]; ok {
			return v, nil
		}
	}
	return dbus.Variant{}, dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{"no such property"})
}

func (p *props) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]dbus.Variant{}
	for k, v := range p.m[iface] {
		out[k] = v
	}
	return out, nil
}

func (p *props) Set(iface, name string, v dbus.Variant) *dbus.Error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.m[iface]; !ok {
		p.m[iface] = map[string]dbus.Variant{}
	}
	p.m[iface][name] = v
	return nil
}

func (p *props) all() map[string]map[string]dbus.Variant {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]map[string]dbus.Variant{}
	for iface, m := range p.m {
		cp := map[string]dbus.Variant{}
		for k, v := range m {
			cp[k] = v
		}
		out[iface] = cp
	}
	return out
}

// --- GATT characteristic ---

type characteristic struct {
	path    dbus.ObjectPath
	uuid    string
	flags   []string
	props   *props
	srv     *gattServer
	readFn  func(options map[string]dbus.Variant) ([]byte, *dbus.Error)
	writeFn func(value []byte, options map[string]dbus.Variant) *dbus.Error

	mu        sync.Mutex
	notifying bool
	cachedVal []byte
}

func (c *characteristic) ReadValue(options map[string]dbus.Variant) ([]byte, *dbus.Error) {
	if c.readFn != nil {
		return c.readFn(options)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.cachedVal...), nil
}

func (c *characteristic) WriteValue(value []byte, options map[string]dbus.Variant) *dbus.Error {
	if c.writeFn != nil {
		return c.writeFn(value, options)
	}
	return dbus.NewError("org.bluez.Error.NotSupported", []interface{}{"write not supported"})
}

func (c *characteristic) StartNotify() *dbus.Error {
	c.mu.Lock()
	c.notifying = true
	c.mu.Unlock()
	if c.uuid == uuidWifiScan && c.srv != nil {
		go c.srv.pushScanChunks()
	}
	return nil
}

func (c *characteristic) StopNotify() *dbus.Error {
	c.mu.Lock()
	c.notifying = false
	c.mu.Unlock()
	return nil
}

func (c *characteristic) notify(value []byte) {
	c.mu.Lock()
	isNotifying := c.notifying
	c.cachedVal = append([]byte(nil), value...)
	c.mu.Unlock()
	if !isNotifying || c.srv == nil || c.srv.conn == nil {
		return
	}
	changed := map[string]dbus.Variant{"Value": dbus.MakeVariant(value)}
	_ = c.srv.conn.Emit(c.path, "org.freedesktop.DBus.Properties.PropertiesChanged",
		"org.bluez.GattCharacteristic1", changed, []string{})
}

// --- GATT service ---

type service struct{ props *props }

func (s *service) dummy() {}

// --- application root (ObjectManager) ---

type gattApp struct {
	objects map[dbus.ObjectPath]map[string]map[string]dbus.Variant
}

func (a *gattApp) GetManagedObjects() (map[dbus.ObjectPath]map[string]map[string]dbus.Variant, *dbus.Error) {
	return a.objects, nil
}

// --- advertisement (org.bluez.LEAdvertisement1) ---

type advertisement struct{ props *props }

func (a *advertisement) Release() *dbus.Error {
	log.Printf("advertisement released by BlueZ")
	return nil
}

// --- pairing agent (org.bluez.Agent1, KeyboardOnly, fixed setup code) ---

type agent struct{}

func (a *agent) Release() *dbus.Error { return nil }

func (a *agent) RequestPinCode(device dbus.ObjectPath) (string, *dbus.Error) {
	return identity.SetupCode, nil
}

// RequestPasskey returns the per-device 6-digit setup code from identity.json.
func (a *agent) RequestPasskey(device dbus.ObjectPath) (uint32, *dbus.Error) {
	n, err := strconv.ParseUint(strings.TrimSpace(identity.SetupCode), 10, 32)
	if err != nil {
		return 0, dbus.NewError("org.bluez.Error.Rejected", []interface{}{"no setup code provisioned"})
	}
	return uint32(n % 1000000), nil
}

func (a *agent) DisplayPasskey(device dbus.ObjectPath, passkey uint32, entered uint16) *dbus.Error {
	return nil
}

func (a *agent) RequestConfirmation(device dbus.ObjectPath, passkey uint32) *dbus.Error {
	if pairingLockedOut() {
		return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"pairing locked out"})
	}
	want, err := strconv.ParseUint(strings.TrimSpace(identity.SetupCode), 10, 32)
	if err == nil && uint32(want%1000000) == passkey {
		return nil
	}
	recordPairingFailure()
	return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"passkey mismatch"})
}

// Authorization is NOT blanket (F9): only the recorded owner (by bond
// identity) is authorized; before any owner exists, pairing itself is
// the gate and service authorization follows a successful bond.
func (a *agent) RequestAuthorization(device dbus.ObjectPath) *dbus.Error {
	if pairingLockedOut() {
		return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"pairing locked out"})
	}
	if ownerRecorded() && !deviceIsOwner(device) {
		return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"not the owner"})
	}
	return nil
}
func (a *agent) AuthorizeService(device dbus.ObjectPath, uuid string) *dbus.Error {
	if pairingLockedOut() {
		return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"pairing locked out"})
	}
	if ownerRecorded() && !deviceIsOwner(device) {
		return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"not the owner"})
	}
	return nil
}

// Cancel fires when a pairing attempt is aborted/failed — count it
// toward the §F4 lockout (a successful bond clears the counter).
func (a *agent) Cancel() *dbus.Error {
	recordPairingFailure()
	return nil
}

// --- server ---

type gattServer struct {
	conn  *dbus.Conn
	chars map[string]*characteristic
	advOn bool
	mu    sync.Mutex

	scanMu     sync.Mutex
	scanChunks [][]byte
	scanIdx    int

	vpnMu        sync.Mutex
	vpnBuf       []byte
	vpnNextSeq   int
	windowClosed bool
}

var gattSrv *gattServer

func deviceFromOptions(options map[string]dbus.Variant) string {
	if v, ok := options["device"]; ok {
		if p, ok := v.Value().(dbus.ObjectPath); ok {
			return string(p)
		}
		if s, ok := v.Value().(string); ok {
			return s
		}
	}
	return ""
}

// --- Owner identity (§F4, F9): the BlueZ bond record, not the
// momentary device path. owner.json holds the identity address + IRK
// read from /var/lib/bluetooth; BlueZ resolves the owner's rotating
// RPA via the IRK, and the D-Bus Device1.Address of a connected peer
// is the resolved identity address. ---

type ownerRecord struct {
	Address string `json:"address"`
	IRK     string `json:"irk,omitempty"`
}

const ownerJSONPath = cfgDir + "/owner.json"
const bluetoothStateDir = "/var/lib/bluetooth"

func loadOwner() (ownerRecord, bool) {
	b, err := os.ReadFile(ownerJSONPath)
	if err != nil {
		return ownerRecord{}, false
	}
	var o ownerRecord
	if json.Unmarshal(b, &o) != nil || o.Address == "" {
		return ownerRecord{}, false
	}
	return o, true
}

func ownerRecorded() bool { _, ok := loadOwner(); return ok }

// deviceAddress resolves a BlueZ device object path to its identity
// address via D-Bus (post-bond this is IRK-resolved by BlueZ).
func deviceAddress(path string) string {
	if gattSrv == nil || gattSrv.conn == nil || path == "" {
		return ""
	}
	obj := gattSrv.conn.Object("org.bluez", dbus.ObjectPath(path))
	v, err := obj.GetProperty("org.bluez.Device1.Address")
	if err != nil {
		return ""
	}
	if s, ok := v.Value().(string); ok {
		return strings.ToUpper(s)
	}
	return ""
}

// readBondIRK reads the IdentityResolvingKey for an identity address
// from the BlueZ bond store /var/lib/bluetooth/<adapter>/<device>/info.
func readBondIRK(address string) string {
	adapters, _ := os.ReadDir(bluetoothStateDir)
	for _, a := range adapters {
		if !a.IsDir() {
			continue
		}
		info, err := os.ReadFile(filepath.Join(bluetoothStateDir, a.Name(), strings.ToUpper(address), "info"))
		if err != nil {
			continue
		}
		inIRK := false
		for _, line := range strings.Split(string(info), "\n") {
			line = strings.TrimSpace(line)
			if line == "[IdentityResolvingKey]" {
				inIRK = true
				continue
			}
			if strings.HasPrefix(line, "[") {
				inIRK = false
			}
			if inIRK && strings.HasPrefix(line, "Key=") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Key="))
			}
		}
	}
	return ""
}

// claimOwner records the first bonded peer's bond identity as owner;
// later peers are rejected until unbond/factory reset.
func claimOwner(options map[string]dbus.Variant) *dbus.Error {
	if _, ok := loadOwner(); ok {
		if isOwner(options) {
			return nil
		}
		return dbus.NewError("org.bluez.Error.NotAuthorized",
			[]interface{}{"device is owned by another bonded peer; unbond from the owner app or factory-reset"})
	}
	dev := deviceFromOptions(options)
	addr := deviceAddress(dev)
	if addr == "" {
		// Fail closed (F9): an unidentifiable peer cannot become owner
		// and cannot write config.
		return dbus.NewError("org.bluez.Error.NotAuthorized",
			[]interface{}{"peer identity unavailable; cannot claim ownership"})
	}
	rec := ownerRecord{Address: addr, IRK: readBondIRK(addr)}
	b, _ := json.Marshal(rec)
	if err := writeFileAtomic(ownerJSONPath, append(b, '\n'), 0o600); err != nil {
		return dbus.MakeFailedError(err)
	}
	clearPairingFailures()
	log.Printf("owner claimed: bond identity address recorded (irk present: %v)", rec.IRK != "")
	return nil
}

func deviceIsOwner(path dbus.ObjectPath) bool {
	o, ok := loadOwner()
	if !ok {
		return false
	}
	return deviceAddress(string(path)) == o.Address
}

// isOwner FAILS CLOSED (F9): with an owner recorded, an unidentifiable
// peer is not the owner. With no owner recorded yet, writes are gated
// by claimOwner instead (first bonded peer claims, others rejected).
func isOwner(options map[string]dbus.Variant) bool {
	o, ok := loadOwner()
	if !ok {
		return true
	}
	dev := deviceFromOptions(options)
	if dev == "" {
		return false
	}
	return deviceAddress(dev) == o.Address
}

func requireOwner(options map[string]dbus.Variant) *dbus.Error {
	if !isOwner(options) {
		return authErr("not the owner")
	}
	return nil
}

// --- Pairing lockout (§F4): 5 failures in a window -> window closes,
// bonding locked 15 min, doubling per lockout, cap 60 min; persisted
// in state.json (store.lk). Success or factory reset clears it. ---

func pairingLockedOut() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return time.Now().Unix() < store.lk.LockedUntil
}

func recordPairingFailure() {
	store.mu.Lock()
	store.lk.FailCount++
	n := store.lk.FailCount
	trigger := n >= 5
	if trigger {
		store.lk.FailCount = 0
		store.lk.LockoutCount++
		dur := 15 * time.Minute << (store.lk.LockoutCount - 1)
		if dur > 60*time.Minute {
			dur = 60 * time.Minute
		}
		store.lk.LockedUntil = time.Now().Add(dur).Unix()
	}
	store.mu.Unlock()
	store.persist()
	if trigger {
		log.Printf("pairing lockout: 5 failed attempts — window closed, bonding locked (see state.json)")
		if gattSrv != nil {
			gattSrv.CloseWindow()
		}
	}
}

func clearPairingFailures() {
	store.mu.Lock()
	store.lk = lockoutState{}
	store.mu.Unlock()
	store.persist()
}

func authErr(msg string) *dbus.Error {
	// BlueZ maps this to ATT Insufficient Authentication for unbonded peers;
	// encryption itself is enforced by the characteristic flags below.
	return dbus.NewError("org.bluez.Error.NotAuthorized", []interface{}{msg})
}

func (s *gattServer) pushScanChunks() {
	s.scanMu.Lock()
	chunks := scanChunks()
	s.scanChunks = chunks
	s.scanIdx = 0
	s.scanMu.Unlock()
	if c := s.chars[uuidWifiScan]; c != nil {
		for _, ch := range chunks {
			c.notify(ch)
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func buildChars(s *gattServer) []*characteristic {
	mk := func(i int, uuid string, flags []string,
		readFn func(map[string]dbus.Variant) ([]byte, *dbus.Error),
		writeFn func([]byte, map[string]dbus.Variant) *dbus.Error) *characteristic {
		c := &characteristic{
			path: charPath(i), uuid: uuid, flags: flags, srv: s, readFn: readFn, writeFn: writeFn,
			props: &props{m: map[string]map[string]dbus.Variant{
				"org.bluez.GattCharacteristic1": {
					"UUID":           dbus.MakeVariant(uuid),
					"Service":        dbus.MakeVariant(svcPath),
					"Flags":          dbus.MakeVariant(flags),
					"Notifying":      dbus.MakeVariant(false),
					"WriteAcquired":  dbus.MakeVariant(false),
					"NotifyAcquired": dbus.MakeVariant(false),
				},
			}},
		}
		return c
	}
	encRead := []string{"read", "encrypt-read"}
	encReadNotify := []string{"read", "notify", "encrypt-read"}
	encWrite := []string{"write", "encrypt-write", "secure-write"}

	chars := []*characteristic{
		// DeviceInfo: Read, NOT encrypted, JSON ≤128 B {model, serial, fw}.
		mk(0, uuidDeviceInfo, []string{"read"}, func(map[string]dbus.Variant) ([]byte, *dbus.Error) {
			b, _ := json.Marshal(map[string]string{
				"model": modelName, "serial": identity.Serial, "fw": fwVersion,
			})
			if len(b) > 128 {
				b, _ = json.Marshal(map[string]string{"model": "HSL", "serial": last4(identity.Serial), "fw": fwVersion})
			}
			return b, nil
		}, nil),
		// WifiScan: Read+Notify, encrypted. Read triggers a scan and returns
		// successive ≤182 B chunks on repeated reads.
		mk(1, uuidWifiScan, encReadNotify, func(options map[string]dbus.Variant) ([]byte, *dbus.Error) {
			if err := requireOwner(options); err != nil {
				return nil, err
			}
			if isTxActive() {
				// §F4: scan is refused with error=busy mid-transaction.
				store.update(func(st *State) { st.Error = "busy" })
				return []byte(`{"idx":0,"total":0,"ssid":"","bssid":"","rssi":0,"band":"","channel":0,"security":"open","secure":false}`), nil
			}
			s.scanMu.Lock()
			defer s.scanMu.Unlock()
			if len(s.scanChunks) == 0 || s.scanIdx >= len(s.scanChunks) {
				store.set("scanning", "")
				s.scanChunks = scanChunks()
				s.scanIdx = 0
				store.set("idle", "")
			}
			ch := s.scanChunks[s.scanIdx]
			s.scanIdx++
			return ch, nil
		}, nil),
		// WifiConfig: Write, encrypted+bonded, JSON ≤512 B.
		mk(2, uuidWifiConfig, encWrite, nil, func(value []byte, options map[string]dbus.Variant) *dbus.Error {
			if err := claimOwner(options); err != nil {
				return err
			}
			if len(value) > 512 {
				return dbus.NewError("org.bluez.Error.InvalidValueLength", []interface{}{"WifiConfig >512B"})
			}
			go func() {
				if err := applyWifiTransaction(append([]byte(nil), value...)); err != nil {
					log.Printf("wifi apply: %v", err)
					return
				}
				checkCaptiveAndVPN()
			}()
			return nil
		}),
		// VpnConfig: Write, encrypted+bonded, ≤4096 B (updated spec).
		// §4.2: a first byte of '{' is a complete unchunked payload;
		// chunked mode uses a 1-byte seq header, a chunk with <181
		// payload bytes is final, and an exactly-full final chunk is
		// followed by a header-only terminating chunk. Validation is
		// synchronous on the final chunk via Status error codes.
		mk(3, uuidVpnConfig, encWrite, nil, func(value []byte, options map[string]dbus.Variant) *dbus.Error {
			if err := claimOwner(options); err != nil {
				return err
			}
			if len(value) < 1 {
				return dbus.NewError("org.bluez.Error.InvalidValueLength", []interface{}{"empty chunk"})
			}
			finish := func(payload []byte) *dbus.Error {
				if _, code := validateVpnPayload(payload); code != "" {
					store.set("vpn_failed", code)
					return nil // stored nothing; failure is synchronous via Status (§4.2 rule 5 as amended)
				}
				buf := append([]byte(nil), payload...)
				go func() {
					if err := applyVpnConfig(buf); err != nil {
						log.Printf("vpn apply: %v", err)
						store.set("vpn_failed", "vpn_config_invalid")
						return
					}
					// F2: `online` only after the §F4 raise+validation,
					// and only when Wi-Fi/internet already check out.
					if wifiOnline() {
						checkCaptiveAndVPN()
					}
				}()
				return nil
			}
			if value[0] == '{' {
				s.vpnMu.Lock()
				s.vpnBuf = nil
				s.vpnNextSeq = 0
				s.vpnMu.Unlock()
				return finish(value)
			}
			seq := int(value[0])
			payload := value[1:]
			s.vpnMu.Lock()
			if seq == 0 {
				s.vpnBuf = nil
				s.vpnNextSeq = 0
			}
			if seq != s.vpnNextSeq {
				s.vpnBuf = nil
				s.vpnNextSeq = 0
				s.vpnMu.Unlock()
				return dbus.NewError("org.bluez.Error.InvalidOffset", []interface{}{fmt.Sprintf("vpn chunk seq %d out of order", seq)})
			}
			s.vpnBuf = append(s.vpnBuf, payload...)
			s.vpnNextSeq++
			if len(s.vpnBuf) > vpnConfigCeiling {
				s.vpnBuf = nil
				s.vpnNextSeq = 0
				s.vpnMu.Unlock()
				store.set("vpn_failed", "vpn_config_invalid")
				return dbus.NewError("org.bluez.Error.InvalidValueLength", []interface{}{"VpnConfig >4096B"})
			}
			final := len(payload) < 181 // includes the header-only terminator (len 0)
			buf := append([]byte(nil), s.vpnBuf...)
			if final {
				s.vpnBuf = nil
				s.vpnNextSeq = 0
			}
			s.vpnMu.Unlock()
			if final {
				return finish(buf)
			}
			return nil
		}),
		// Status: Read+Notify, encrypted, JSON ≤128 B.
		mk(4, uuidStatus, encReadNotify, func(options map[string]dbus.Variant) ([]byte, *dbus.Error) {
			if err := requireOwner(options); err != nil {
				return nil, err
			}
			return store.json(), nil
		}, nil),
		// Control: Write, encrypted+bonded.
		mk(5, uuidControl, encWrite, nil, func(value []byte, options map[string]dbus.Variant) *dbus.Error {
			if err := claimOwner(options); err != nil {
				return err
			}
			var cmd struct {
				Cmd string `json:"cmd"`
			}
			if err := json.Unmarshal(value, &cmd); err != nil {
				return dbus.NewError("org.bluez.Error.InvalidArguments", []interface{}{"control JSON"})
			}
			if !knownControlCmd(cmd.Cmd) {
				// gatt.md: any other cmd is rejected and changes nothing.
				return dbus.NewError("org.bluez.Error.InvalidArguments", []interface{}{"unknown cmd"})
			}
			go handleControl(cmd.Cmd, options, s)
			return nil
		}),
	}
	// secure-read variants: BlueZ accepts "encrypt-read" for LE Secure
	// Connections bonding enforcement; DeviceInfo intentionally stays plain.
	_ = encRead
	return chars
}

func startGATT() (*gattServer, error) {
	s := &gattServer{chars: map[string]*characteristic{}}
	gattSrv = s
	// Status notifications follow state changes.
	store.onChange = func(st State) {
		if c := s.chars[uuidStatus]; c != nil {
			c.notify(store.json())
		}
		if st.State == "online" || st.State == "online_no_vpn" {
			// §F4: the window also closes by itself at online.
			go s.CloseWindow()
		}
	}
	go func() {
		for {
			if err := s.connect(); err != nil {
				log.Printf("GATT connect: %v (retry in 15s; BT may still be attaching)", err)
				time.Sleep(15 * time.Second)
				continue
			}
			log.Printf("GATT server registered on %s", adapterPath)
			return
		}
	}()
	return s, nil
}

func (s *gattServer) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *gattServer) connect() error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}
	s.conn = conn

	chars := buildChars(s)
	objects := map[dbus.ObjectPath]map[string]map[string]dbus.Variant{}

	svcProps := &props{m: map[string]map[string]dbus.Variant{
		"org.bluez.GattService1": {
			"UUID":    dbus.MakeVariant(uuidService),
			"Primary": dbus.MakeVariant(true),
			"Device":  dbus.MakeVariant(adapterPath),
		},
	}}
	objects[svcPath] = svcProps.all()
	if err := conn.Export(&service{props: svcProps}, svcPath, "org.bluez.GattService1"); err != nil {
		return err
	}
	if err := conn.Export(svcProps, svcPath, "org.freedesktop.DBus.Properties"); err != nil {
		return err
	}

	for _, c := range chars {
		s.chars[c.uuid] = c
		objects[c.path] = c.props.all()
		if err := conn.Export(c, c.path, "org.bluez.GattCharacteristic1"); err != nil {
			return err
		}
		if err := conn.Export(c.props, c.path, "org.freedesktop.DBus.Properties"); err != nil {
			return err
		}
	}

	app := &gattApp{objects: objects}
	if err := conn.Export(app, appPath, "org.freedesktop.DBus.ObjectManager"); err != nil {
		return err
	}

	// Pairing agent: KeyboardOnly, passkey = fixed per-device setup code.
	ag := &agent{}
	if err := conn.Export(ag, agentPath, "org.bluez.Agent1"); err == nil {
		busObj := conn.Object("org.bluez", "/org/bluez")
		call := busObj.Call("org.bluez.AgentManager1.RegisterAgent", 0, agentPath, "keyboard-only")
		if call.Err != nil {
			log.Printf("RegisterAgent(keyboard-only): %v (continuing)", call.Err)
			// Older BlueZ wants the exact capability string casing variant.
			_ = busObj.Call("org.bluez.AgentManager1.RegisterAgent", 0, agentPath, "KeyboardOnly")
		}
		_ = busObj.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, agentPath)
	}

	// Adapter: name HSL-<last4>, powered on.
	s.setAdapterProp("Alias", dbus.MakeVariant("HSL-"+last4(identity.Serial)))
	s.setAdapterProp("Powered", dbus.MakeVariant(true))

	gattMgr := conn.Object("org.bluez", adapterPath)
	call := gattMgr.Call("org.bluez.GattManager1.RegisterApplication", 0, appPath, map[string]dbus.Variant{})
	if call.Err != nil {
		conn.Close()
		return fmt.Errorf("RegisterApplication: %w", call.Err)
	}

	// Advertisement object.
	advProps := &props{m: map[string]map[string]dbus.Variant{
		"org.bluez.LEAdvertisement1": {
			"Type":         dbus.MakeVariant("peripheral"),
			"ServiceUUIDs": dbus.MakeVariant([]string{uuidService}),
			"LocalName":    dbus.MakeVariant("HSL-" + last4(identity.Serial)),
			"Discoverable": dbus.MakeVariant(true),
			"Includes":     dbus.MakeVariant([]string{}),
		},
	}}
	adv := &advertisement{props: advProps}
	if err := conn.Export(adv, advPath, "org.bluez.LEAdvertisement1"); err != nil {
		return err
	}
	if err := conn.Export(advProps, advPath, "org.freedesktop.DBus.Properties"); err != nil {
		return err
	}
	s.mu.Lock()
	s.advOn = false // window manager turns it on
	s.mu.Unlock()
	return nil
}

func (s *gattServer) setAdapterProp(name string, v dbus.Variant) {
	if s.conn == nil {
		return
	}
	obj := s.conn.Object("org.bluez", adapterPath)
	call := obj.Call("org.freedesktop.DBus.Properties.Set", 0, "org.bluez.Adapter1", name, v)
	if call.Err != nil {
		log.Printf("adapter Set %s: %v", name, call.Err)
	}
}

func (s *gattServer) startAdvertising() {
	s.mu.Lock()
	if s.advOn || s.conn == nil {
		s.mu.Unlock()
		return
	}
	s.advOn = true
	s.mu.Unlock()
	obj := s.conn.Object("org.bluez", adapterPath)
	call := obj.Call("org.bluez.LEAdvertisingManager1.RegisterAdvertisement", 0, advPath, map[string]dbus.Variant{})
	if call.Err != nil {
		log.Printf("RegisterAdvertisement: %v", call.Err)
		s.mu.Lock()
		s.advOn = false
		s.mu.Unlock()
		return
	}
	s.setAdapterProp("Discoverable", dbus.MakeVariant(true))
	s.setAdapterProp("Pairable", dbus.MakeVariant(true))
	log.Printf("provisioning window open: advertising as HSL-%s", last4(identity.Serial))
}

func (s *gattServer) stopAdvertising() {
	s.mu.Lock()
	if !s.advOn || s.conn == nil {
		s.mu.Unlock()
		return
	}
	s.advOn = false
	s.mu.Unlock()
	obj := s.conn.Object("org.bluez", adapterPath)
	_ = obj.Call("org.bluez.LEAdvertisingManager1.UnregisterAdvertisement", 0, advPath)
	s.setAdapterProp("Discoverable", dbus.MakeVariant(false))
	log.Printf("provisioning window closed: advertisement stopped, discoverable off")
}

// CloseWindow enforces all three §F4 close actions: advertising
// stops, the adapter goes non-discoverable AND non-pairable, and
// non-owner centrals are disconnected (an owner session continues).
func (s *gattServer) CloseWindow() {
	s.mu.Lock()
	s.windowClosed = true
	s.mu.Unlock()
	s.stopAdvertising()
	s.setAdapterProp("Pairable", dbus.MakeVariant(false))
	s.disconnectNonOwners()
}

func (s *gattServer) disconnectNonOwners() {
	if s.conn == nil {
		return
	}
	om := s.conn.Object("org.bluez", "/")
	// Walk managed objects for connected Device1 peers.
	var objects map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	call := om.Call("org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0)
	if call.Err != nil || call.Store(&objects) != nil {
		return
	}
	owner, hasOwner := loadOwner()
	for path, ifaces := range objects {
		dev, ok := ifaces["org.bluez.Device1"]
		if !ok {
			continue
		}
		connected, _ := dev["Connected"].Value().(bool)
		if !connected {
			continue
		}
		if hasOwner {
			if addr, _ := dev["Address"].Value().(string); strings.EqualFold(addr, owner.Address) {
				continue // the owner's session continues
			}
		}
		obj := s.conn.Object("org.bluez", path)
		_ = obj.Call("org.bluez.Device1.Disconnect", 0)
		log.Printf("window close: disconnected non-owner central %s", path)
	}
}

// provisioningWindowManager (§F4): open 300 s after boot, and permanently
// while no Wi-Fi config exists. Closing = stop advertising + discoverable off.
func provisioningWindowManager() {
	for {
		time.Sleep(5 * time.Second)
		s := gattSrv
		if s == nil || s.conn == nil {
			continue
		}
		s.mu.Lock()
		closed := s.windowClosed
		s.mu.Unlock()
		if closed {
			continue
		}
		open := !hasWifiConfig() || time.Since(bootTime) < 300*time.Second
		if open {
			s.startAdvertising()
		} else {
			// Timeout close gets the FULL §F4 enforcement
			// (non-pairable + non-owner disconnect), not just
			// advertising off (R3-1 window semantics).
			s.CloseWindow()
		}
	}
}

var _ = filepath.Join // keep filepath import if cfg layout changes
