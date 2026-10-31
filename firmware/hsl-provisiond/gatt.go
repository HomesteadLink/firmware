package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

	// attPayloadMax is the §4.3 payload cap: min(182, MTU−3). The
	// apps request MTU 185 (§1), so the working payload is 182;
	// chunking below is payload-relative via the observed chunk
	// size, so a smaller negotiated MTU still reassembles correctly.
	attPayloadMax = 182
)

const emptyScanJSON = `{"idx":0,"total":0,"ssid":"","bssid":"","rssi":0,"band":"2.4","channel":0,"security":"open","secure":false}`

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

// --- §4.2 payload-relative chunk reassembler (client → device) ---
//
// A first byte of '{' is a complete unchunked payload. Otherwise
// byte 0 is the seq header; the session payload is learned from the
// first chunk's total length (chunks are payload-sized except the
// last); a chunk shorter than the session payload — or the
// header-only terminating chunk — is final (amended §4.2 rule 4).

type reassembler struct {
	mu        sync.Mutex
	buf       []byte
	nextSeq   int
	chunkSize int
	ceiling   int
}

func (r *reassembler) resetLocked() {
	r.buf = nil
	r.nextSeq = 0
	r.chunkSize = 0
}

// feed consumes one write value and returns (payload, true, nil)
// when a transfer completes.
func (r *reassembler) feed(value []byte) ([]byte, bool, *dbus.Error) {
	if len(value) < 1 {
		return nil, false, dbus.NewError("org.bluez.Error.InvalidValueLength", []interface{}{"empty write"})
	}
	if value[0] == '{' {
		r.mu.Lock()
		r.resetLocked()
		r.mu.Unlock()
		if len(value) > r.ceiling {
			return nil, false, dbus.NewError("org.bluez.Error.InvalidValueLength", []interface{}{"payload over ceiling"})
		}
		return append([]byte(nil), value...), true, nil
	}
	seq := int(value[0])
	payload := value[1:]
	r.mu.Lock()
	defer r.mu.Unlock()
	if seq == 0 {
		r.resetLocked()
		r.chunkSize = len(value)
	}
	if seq != r.nextSeq {
		r.resetLocked()
		return nil, false, dbus.NewError("org.bluez.Error.InvalidOffset", []interface{}{fmt.Sprintf("chunk seq %d out of order", seq)})
	}
	r.buf = append(r.buf, payload...)
	r.nextSeq++
	if len(r.buf) > r.ceiling {
		r.resetLocked()
		return nil, false, dbus.NewError("org.bluez.Error.InvalidValueLength", []interface{}{"reassembled payload over ceiling"})
	}
	final := len(value) < r.chunkSize || len(value) == 1
	if !final {
		return nil, false, nil
	}
	out := append([]byte(nil), r.buf...)
	r.resetLocked()
	return out, true, nil
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

// StartNotify NEVER triggers a scan (§4.1 as amended / critique f4):
// Read is the only scan trigger; notifications only deliver results.
func (c *characteristic) StartNotify() *dbus.Error {
	c.mu.Lock()
	c.notifying = true
	c.mu.Unlock()
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

// notifyValue sends one value, splitting it into §4.2-format chunks
// when it exceeds the current payload (§4.3 notification rule).
func (c *characteristic) notifyValue(value []byte) {
	if len(value) <= attPayloadMax {
		c.notify(value)
		return
	}
	seq := 0
	rest := value
	for len(rest) > 0 {
		n := attPayloadMax - 1
		if n > len(rest) {
			n = len(rest)
		}
		chunk := append([]byte{byte(seq)}, rest[:n]...)
		rest = rest[n:]
		seq++
		c.notify(chunk)
		if len(rest) == 0 && n == attPayloadMax-1 {
			// Exactly-full final chunk → header-only terminator.
			c.notify([]byte{byte(seq)})
		}
	}
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

// --- Bond store (§F4 exactly-one-bond mechanism) ---

const ownerJSONPath = cfgDir + "/owner.json"
const bluetoothStateDir = "/var/lib/bluetooth"

type ownerRecord struct {
	Address string `json:"address"`
	IRK     string `json:"irk,omitempty"`
}

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

// bondStoreAddrs lists the identity addresses of all bond records in
// /var/lib/bluetooth/<adapter>/ (one device directory per bond),
// oldest first (by directory mtime).
func bondStoreAddrs() []string {
	adapters, _ := os.ReadDir(bluetoothStateDir)
	type ent struct {
		addr string
		mod  time.Time
	}
	var ents []ent
	for _, a := range adapters {
		if !a.IsDir() {
			continue
		}
		devs, _ := os.ReadDir(filepath.Join(bluetoothStateDir, a.Name()))
		for _, d := range devs {
			if !d.IsDir() {
				continue
			}
			p := filepath.Join(bluetoothStateDir, a.Name(), d.Name(), "info")
			fi, err := os.Stat(p)
			if err != nil {
				continue
			}
			ents = append(ents, ent{addr: strings.ToUpper(d.Name()), mod: fi.ModTime()})
		}
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].mod.Before(ents[j].mod) })
	var out []string
	for _, e := range ents {
		out = append(out, e.addr)
	}
	return out
}

// readBondIRK reads the IdentityResolvingKey for an identity address
// from the BlueZ bond store.
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

// pruneBonds enforces exactly-one-bond at startup (§F4): if more
// than one bond record exists, all but the oldest are removed via
// RemoveDevice; a single existing bond with no owner record is
// adopted as the owner (e.g. created while the daemon was down).
func (s *gattServer) pruneBonds() {
	addrs := bondStoreAddrs()
	if len(addrs) > 1 {
		log.Printf("bond store holds %d bonds — removing all but the oldest (exactly-one-bond, §F4)", len(addrs))
		for _, a := range addrs[1:] {
			s.removeDevice(a)
		}
		addrs = addrs[:1]
	}
	if len(addrs) == 1 {
		if _, ok := loadOwner(); !ok {
			rec := ownerRecord{Address: addrs[0], IRK: readBondIRK(addrs[0])}
			b, _ := json.Marshal(rec)
			if err := writeFileAtomic(ownerJSONPath, append(b, '\n'), 0o600); err == nil {
				log.Printf("owner adopted from the existing bond record (irk present: %v)", rec.IRK != "")
			}
		}
	}
}

func (s *gattServer) removeDevice(addr string) {
	if s == nil || s.conn == nil {
		_ = exec.Command("bluetoothctl", "remove", addr).Run()
		return
	}
	path := dbus.ObjectPath("/org/bluez/hci0/dev_" + strings.ReplaceAll(addr, ":", "_"))
	obj := s.conn.Object("org.bluez", adapterPath)
	if call := obj.Call("org.bluez.Adapter1.RemoveDevice", 0, path); call.Err != nil {
		_ = exec.Command("bluetoothctl", "remove", addr).Run()
	}
}

func (s *gattServer) disconnectDevice(path dbus.ObjectPath) {
	if s == nil || s.conn == nil {
		return
	}
	_ = s.conn.Object("org.bluez", path).Call("org.bluez.Device1.Disconnect", 0)
}

// --- Pairing agent (org.bluez.Agent1, KeyboardOnly, setup code) ---

type agent struct{}

func (a *agent) Release() *dbus.Error { return nil }

// agentGuard is the §F4 exactly-one-bond + lockout gate, evaluated
// BEFORE the agent answers any request: locked out → Rejected; a
// bond exists and the requester is not that bond → Rejected and the
// requester is disconnected (no second bond is ever created).
func agentGuard(device dbus.ObjectPath) *dbus.Error {
	if pairingLockedOut() {
		return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"pairing locked out"})
	}
	if addrs := bondStoreAddrs(); len(addrs) >= 1 {
		addr := deviceAddress(string(device))
		isBond := false
		for _, b := range addrs {
			if addr != "" && strings.EqualFold(addr, b) {
				isBond = true
				break
			}
		}
		if !isBond {
			log.Printf("pairing request from a non-bond device rejected + disconnected (exactly-one-bond)")
			if gattSrv != nil {
				gattSrv.disconnectDevice(device)
			}
			return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"device already bonded to its owner"})
		}
	}
	return nil
}

func (a *agent) RequestPinCode(device dbus.ObjectPath) (string, *dbus.Error) {
	if err := agentGuard(device); err != nil {
		return "", err
	}
	return identity.SetupCode, nil
}

// RequestPasskey returns the per-device 6-digit setup code from identity.json.
func (a *agent) RequestPasskey(device dbus.ObjectPath) (uint32, *dbus.Error) {
	if err := agentGuard(device); err != nil {
		return 0, err
	}
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
	if err := agentGuard(device); err != nil {
		return err
	}
	want, err := strconv.ParseUint(strings.TrimSpace(identity.SetupCode), 10, 32)
	if err == nil && uint32(want%1000000) == passkey {
		return nil
	}
	recordPairingFailure()
	return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"passkey mismatch"})
}

func (a *agent) RequestAuthorization(device dbus.ObjectPath) *dbus.Error {
	return agentGuard(device)
}

func (a *agent) AuthorizeService(device dbus.ObjectPath, uuid string) *dbus.Error {
	return agentGuard(device)
}

// Cancel fires when a pairing attempt is aborted/failed — count it
// toward the §F4 lockout (a successful bond clears the counters).
func (a *agent) Cancel() *dbus.Error {
	recordPairingFailure()
	return nil
}

// --- Owner identity (§F4): the BlueZ bond record, never the
// momentary BD_ADDR / device path. BlueZ resolves the owner's
// rotating RPA via the IRK; the D-Bus Device1.Address of a connected
// peer is the resolved identity address. ---

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

// claimOwner records the first bonded peer's bond identity as owner;
// later peers are rejected until unbond/factory reset. Any other
// bond records are removed (exactly-one-bond).
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
		// Fail closed: an unidentifiable peer cannot become owner
		// and cannot write config.
		return dbus.NewError("org.bluez.Error.NotAuthorized",
			[]interface{}{"peer identity unavailable; cannot claim ownership"})
	}
	rec := ownerRecord{Address: addr, IRK: readBondIRK(addr)}
	b, _ := json.Marshal(rec)
	if err := writeFileAtomic(ownerJSONPath, append(b, '\n'), 0o600); err != nil {
		return dbus.MakeFailedError(err)
	}
	for _, other := range bondStoreAddrs() {
		if !strings.EqualFold(other, addr) {
			_ = exec.Command("bluetoothctl", "remove", other).Run()
			log.Printf("claimOwner: removed a non-owner bond record (exactly-one-bond)")
		}
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

// isOwner FAILS CLOSED: with an owner recorded, an unidentifiable
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

// --- Pairing lockout (§F4, powered-time form) ---
//
// Failed passkey attempts are counted in state.json. Window = 60 min
// of POWERED time (monotonic countdown in main.go's lockoutTicker,
// persisted ≥ every 10 s and on every failure). 5 failures inside
// one window → window closes immediately, pair_failures resets,
// lockout_count increments, bonding locks for 15 min of powered
// time, doubled per lockout (cap 60 min). lockout_count resets ONLY
// on a successful bond or a factory reset (Decision Log 41).

func pairingLockedOut() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.lk.LockoutRemainingS > 0
}

func recordPairingFailure() {
	store.mu.Lock()
	if store.lk.LockoutRemainingS > 0 {
		store.mu.Unlock()
		return
	}
	if store.lk.PairWindowRemainingS <= 0 {
		store.lk.PairWindowRemainingS = 3600 // window opens at first failure
		store.lk.PairFailures = 0
	}
	store.lk.PairFailures++
	n := store.lk.PairFailures
	trigger := n >= 5
	if trigger {
		store.lk.PairFailures = 0
		store.lk.LockoutCount++
		dur := 900 << (store.lk.LockoutCount - 1)
		if dur > 3600 {
			dur = 3600
		}
		store.lk.LockoutRemainingS = dur
	}
	store.mu.Unlock()
	store.persist()
	if trigger {
		log.Printf("pairing lockout: 5 failed attempts in the window — window closed, bonding locked for %d powered seconds (lockout #%d)", store.lk.LockoutRemainingS, store.lk.LockoutCount)
		if gattSrv != nil {
			gattSrv.CloseWindow()
		}
	}
}

// clearPairingFailures resets ALL lockout counters — called on a
// successful bond (claim) and on factory reset, nowhere else.
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

// --- server ---

type gattServer struct {
	conn     *dbus.Conn
	chars    map[string]*characteristic
	advProps *props
	advOn    bool
	advMode  string // "" | "open" | "closed"
	mu       sync.Mutex

	windowClosed bool

	scanMu      sync.Mutex
	scanVals    [][]byte
	scanRunning bool

	wifiReasm reassembler
	vpnReasm  reassembler
}

var gattSrv *gattServer

// triggerScan starts ONE asynchronous scan (§F4/§F8 13.10): Status
// stays `scanning` until results are ready or the 15 s timeout; a
// scan during a join/VPN transaction is refused with error=busy.
func (s *gattServer) triggerScan() {
	if isTxActive() {
		store.update(func(st *State) { st.Error = "busy" })
		return
	}
	s.scanMu.Lock()
	if s.scanRunning {
		s.scanMu.Unlock()
		return
	}
	s.scanRunning = true
	s.scanMu.Unlock()
	if store.get().State == "idle" {
		store.set("scanning", "")
	}
	go func() {
		results := scanWifi()
		vals := renderScanValues(results)
		s.scanMu.Lock()
		s.scanVals = vals
		s.scanRunning = false
		s.scanMu.Unlock()
		if c := s.chars[uuidWifiScan]; c != nil {
			for _, v := range vals {
				c.notifyValue(v)
			}
		}
		if store.get().State == "scanning" {
			store.set("idle", "")
		}
	}()
}

// lastScanValue is what a WifiScan Read returns: the MOST RECENT
// value (§4.1 as amended) — the last notification of the latest scan,
// or the empty-scan object before the first scan completes.
func (s *gattServer) lastScanValue() []byte {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if len(s.scanVals) > 0 {
		return append([]byte(nil), s.scanVals[len(s.scanVals)-1]...)
	}
	if c := s.chars[uuidWifiScan]; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if len(c.cachedVal) > 0 {
			return append([]byte(nil), c.cachedVal...)
		}
	}
	return []byte(emptyScanJSON)
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
	encReadNotify := []string{"read", "notify", "encrypt-read"}
	encWrite := []string{"write", "encrypt-write", "secure-write"}

	chars := []*characteristic{
		// DeviceInfo: Read, NOT encrypted, JSON ≤128 B {model, serial, fw}.
		// The serial is NEVER truncated (§F8 13.7); if the object would
		// exceed 128 B the model string shortens instead.
		mk(0, uuidDeviceInfo, []string{"read"}, func(map[string]dbus.Variant) ([]byte, *dbus.Error) {
			b, _ := json.Marshal(map[string]string{
				"model": modelName, "serial": identity.Serial, "fw": fwVersion,
			})
			if len(b) > 128 {
				b, _ = json.Marshal(map[string]string{"model": "HSL", "serial": identity.Serial, "fw": fwVersion})
			}
			return b, nil
		}, nil),
		// WifiScan: Read+Notify, encrypted. Read is the ONLY scan
		// trigger (f4); it starts an asynchronous scan and returns
		// the most recent value (§4.1 as amended). Results stream as
		// notifications in idx order.
		mk(1, uuidWifiScan, encReadNotify, func(options map[string]dbus.Variant) ([]byte, *dbus.Error) {
			if err := requireOwner(options); err != nil {
				return nil, err
			}
			if isTxActive() {
				// §F4: scan refused with error=busy mid-transaction;
				// the read still returns the most recent value.
				store.update(func(st *State) { st.Error = "busy" })
				return s.lastScanValue(), nil
			}
			s.triggerScan()
			return s.lastScanValue(), nil
		}, nil),
		// WifiConfig: Write, encrypted+bonded, JSON ≤512 B, §4.2
		// chunking whenever it exceeds the current payload (§4.3).
		// Final-chunk validation is SYNCHRONOUS (§4.2 rule 7):
		// invalid → nothing stored, no join, error=wifi_config_invalid.
		mk(2, uuidWifiConfig, encWrite, nil, func(value []byte, options map[string]dbus.Variant) *dbus.Error {
			if err := claimOwner(options); err != nil {
				return err
			}
			payload, done, derr := s.wifiReasm.feed(value)
			if derr != nil {
				return derr
			}
			if !done {
				return nil
			}
			p, code := validateWifiPayload(payload)
			if code != "" {
				store.update(func(st *State) { st.Error = code })
				log.Printf("WifiConfig rejected synchronously: %s (nothing stored, no join)", code)
				return nil
			}
			if securityClass(*p) == "eap" {
				store.set("idle", "unsupported_eap")
				log.Printf("WifiConfig rejected synchronously: EAP network (unsupported_eap), nothing stored")
				return nil
			}
			go runWifiTransaction(p)
			return nil
		}),
		// VpnConfig: Write, encrypted+bonded, ≤4096 B. (§4.2 rule 5:
		// final-chunk validation is synchronous.) A valid write is
		// STAGED via the one staging rule (candidate → commit point);
		// it never raises the VPN by itself and never sets a terminal
		// state (f3 / §F8 13.9).
		mk(3, uuidVpnConfig, encWrite, nil, func(value []byte, options map[string]dbus.Variant) *dbus.Error {
			if err := claimOwner(options); err != nil {
				return err
			}
			payload, done, derr := s.vpnReasm.feed(value)
			if derr != nil {
				return derr
			}
			if !done {
				return nil
			}
			if _, code := stageVpnConfig(payload); code != "" {
				store.update(func(st *State) { st.Error = code })
				log.Printf("VpnConfig rejected synchronously: %s (nothing stored)", code)
				return nil
			}
			if isTxActive() {
				log.Printf("VpnConfig staged in candidate/ for the running transaction's VPN phase (DL44)")
			} else {
				commitStagedVpnNow()
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
	return chars
}

func startGATT() (*gattServer, error) {
	s := &gattServer{chars: map[string]*characteristic{}}
	s.wifiReasm = reassembler{ceiling: 512}
	s.vpnReasm = reassembler{ceiling: vpnConfigCeiling}
	gattSrv = s
	// Status notifications follow state changes.
	store.onChange = func(st State) {
		if c := s.chars[uuidStatus]; c != nil {
			c.notifyValue(store.json())
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

	// Pairing agent: KeyboardOnly, passkey = per-device setup code.
	ag := &agent{}
	if err := conn.Export(ag, agentPath, "org.bluez.Agent1"); err == nil {
		busObj := conn.Object("org.bluez", "/org/bluez")
		call := busObj.Call("org.bluez.AgentManager1.RegisterAgent", 0, agentPath, "keyboard-only")
		if call.Err != nil {
			log.Printf("RegisterAgent(keyboard-only): %v (continuing)", call.Err)
			_ = busObj.Call("org.bluez.AgentManager1.RegisterAgent", 0, agentPath, "KeyboardOnly")
		}
		_ = busObj.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, agentPath)
	}

	// Adapter: name HSL-<last4>, powered on.
	s.setAdapterProp("Alias", dbus.MakeVariant("HSL-"+last4(identity.Serial)))
	s.setAdapterProp("Powered", dbus.MakeVariant(true))

	// Exactly-one-bond housekeeping BEFORE GATT registration (§F4).
	s.pruneBonds()

	gattMgr := conn.Object("org.bluez", adapterPath)
	call := gattMgr.Call("org.bluez.GattManager1.RegisterApplication", 0, appPath, map[string]dbus.Variant{})
	if call.Err != nil {
		conn.Close()
		return fmt.Errorf("RegisterApplication: %w", call.Err)
	}

	// Advertisement object (props are mutated by applyAdv as the
	// window opens/closes: open = service UUID + discoverable;
	// closed = connectable, non-discoverable, NO service UUID).
	advProps := &props{m: map[string]map[string]dbus.Variant{
		"org.bluez.LEAdvertisement1": {
			"Type":         dbus.MakeVariant("peripheral"),
			"ServiceUUIDs": dbus.MakeVariant([]string{uuidService}),
			"LocalName":    dbus.MakeVariant("HSL-" + last4(identity.Serial)),
			"Discoverable": dbus.MakeVariant(true),
			"Includes":     dbus.MakeVariant([]string{}),
		},
	}}
	s.advProps = advProps
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

// applyAdv (re)registers the advertisement in the given window mode
// and sets the adapter's Discoverable/Pairable properties — the
// window mechanism is provisiond-driven (§F4); main.conf's timeouts
// are only a backstop.
func (s *gattServer) applyAdv(open bool) {
	if s.conn == nil || s.advProps == nil {
		return
	}
	obj := s.conn.Object("org.bluez", adapterPath)
	s.mu.Lock()
	if s.advOn {
		_ = obj.Call("org.bluez.LEAdvertisingManager1.UnregisterAdvertisement", 0, advPath)
		s.advOn = false
	}
	s.mu.Unlock()
	mode := "closed"
	uuids := []string{}
	if open {
		mode = "open"
		uuids = []string{uuidService}
	}
	_ = s.advProps.Set("org.bluez.LEAdvertisement1", "ServiceUUIDs", dbus.MakeVariant(uuids))
	_ = s.advProps.Set("org.bluez.LEAdvertisement1", "Discoverable", dbus.MakeVariant(open))
	call := obj.Call("org.bluez.LEAdvertisingManager1.RegisterAdvertisement", 0, advPath, map[string]dbus.Variant{})
	s.mu.Lock()
	if call.Err != nil {
		log.Printf("RegisterAdvertisement (%s mode): %v", mode, call.Err)
	} else {
		s.advOn = true
		s.advMode = mode
	}
	s.mu.Unlock()
	s.setAdapterProp("Discoverable", dbus.MakeVariant(open))
	s.setAdapterProp("Pairable", dbus.MakeVariant(open))
	log.Printf("provisioning window %s: advertising %s (discoverable=%v, pairable=%v)", mode, mode, open, open)
}

func (s *gattServer) startAdvertising() {
	s.mu.Lock()
	already := s.advOn && s.advMode == "open"
	s.mu.Unlock()
	if !already {
		s.applyAdv(true)
	}
}

// CloseWindow (§F4 as amended): advertising CONTINUES as connectable,
// non-discoverable, without the service UUID; the adapter goes
// non-discoverable AND non-pairable; non-owner centrals are
// disconnected (the bonded owner's session continues, and the owner
// may reconnect at any time via the OS bond record).
func (s *gattServer) CloseWindow() {
	s.mu.Lock()
	s.windowClosed = true
	s.mu.Unlock()
	s.applyAdv(false)
	s.disconnectNonOwners()
}

func (s *gattServer) disconnectNonOwners() {
	if s.conn == nil {
		return
	}
	om := s.conn.Object("org.bluez", "/")
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

// provisioningWindowManager (§F4): the window is open for 300 s of
// POWERED time after boot (uptime clock, not daemon start) and
// permanently while no Wi-Fi config exists.
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
		if !hasWifiConfig() || uptimeSeconds() < 300 {
			s.startAdvertising()
		} else {
			s.CloseWindow()
		}
	}
}
