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
	ownerPath   = cfgDir + "/owner.txt"
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
	want, err := strconv.ParseUint(strings.TrimSpace(identity.SetupCode), 10, 32)
	if err == nil && uint32(want%1000000) == passkey {
		return nil
	}
	return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"passkey mismatch"})
}

func (a *agent) RequestAuthorization(device dbus.ObjectPath) *dbus.Error { return nil }
func (a *agent) AuthorizeService(device dbus.ObjectPath, uuid string) *dbus.Error {
	return nil
}
func (a *agent) Cancel() *dbus.Error { return nil }

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

// claimOwner records the first bonded peer as owner (§F4); later peers
// writing config/control are rejected until unbond/factory reset.
func claimOwner(options map[string]dbus.Variant) *dbus.Error {
	dev := deviceFromOptions(options)
	if dev == "" {
		return nil // BlueZ normally supplies it; nothing to bind to
	}
	if b, err := os.ReadFile(ownerPath); err == nil {
		if strings.TrimSpace(string(b)) == dev {
			return nil
		}
		return dbus.NewError("org.bluez.Error.NotAuthorized",
			[]interface{}{"device is owned by another bonded peer; unbond from the owner app or factory-reset"})
	}
	_ = os.MkdirAll(cfgDir, 0o755)
	if err := writeFileAtomic(ownerPath, []byte(dev+"\n"), 0o600); err != nil {
		return dbus.MakeFailedError(err)
	}
	log.Printf("owner claimed by bonded peer %s", dev)
	return nil
}

func ownerDevice() string {
	b, err := os.ReadFile(ownerPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func isOwner(options map[string]dbus.Variant) bool {
	owner := ownerDevice()
	if owner == "" {
		return true
	}
	dev := deviceFromOptions(options)
	return dev == "" || dev == owner
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
		mk(1, uuidWifiScan, encReadNotify, func(map[string]dbus.Variant) ([]byte, *dbus.Error) {
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
		// VpnConfig: Write, encrypted+bonded, ≤2048 B, 1-byte seq prefix chunks.
		mk(3, uuidVpnConfig, encWrite, nil, func(value []byte, options map[string]dbus.Variant) *dbus.Error {
			if err := claimOwner(options); err != nil {
				return err
			}
			if len(value) < 1 {
				return dbus.NewError("org.bluez.Error.InvalidValueLength", []interface{}{"empty chunk"})
			}
			seq := int(value[0])
			s.vpnMu.Lock()
			if seq == 0 {
				s.vpnBuf = nil
				s.vpnNextSeq = 0
			}
			if seq != s.vpnNextSeq {
				s.vpnBuf = nil
				s.vpnNextSeq = 0
				s.vpnMu.Unlock()
				return dbus.NewError("org.bluez.Error.InvalidOffset", []interface{}{fmt.Sprintf("vpn chunk seq %d, expected reset", seq)})
			}
			s.vpnBuf = append(s.vpnBuf, value[1:]...)
			s.vpnNextSeq++
			if len(s.vpnBuf) > 2048 {
				s.vpnBuf = nil
				s.vpnNextSeq = 0
				s.vpnMu.Unlock()
				return dbus.NewError("org.bluez.Error.InvalidValueLength", []interface{}{"VpnConfig >2048B"})
			}
			buf := append([]byte(nil), s.vpnBuf...)
			// Complete when the reassembled payload parses as the schema.
			var probe VpnConfigPayload
			complete := json.Unmarshal(buf, &probe) == nil && probe.Type != ""
			if complete {
				s.vpnBuf = nil
				s.vpnNextSeq = 0
			}
			s.vpnMu.Unlock()
			if complete {
				go func() {
					if err := applyVpnConfig(buf); err != nil {
						log.Printf("vpn apply: %v", err)
						store.set("idle", "vpn_failed")
						return
					}
					store.set("online", "")
				}()
			}
			return nil
		}),
		// Status: Read+Notify, encrypted, JSON ≤128 B.
		mk(4, uuidStatus, encReadNotify, func(map[string]dbus.Variant) ([]byte, *dbus.Error) {
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

func (s *gattServer) CloseWindow() {
	s.mu.Lock()
	s.windowClosed = true
	s.mu.Unlock()
	s.stopAdvertising()
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
			s.stopAdvertising()
		}
	}
}

var _ = filepath.Join // keep filepath import if cfg layout changes
