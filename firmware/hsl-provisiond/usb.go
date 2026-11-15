// usb.go — USB transport for hsl-provisiond (WebUSB / FunctionFS).
//
// Trust: physical USB presence. No setup code, no owner token, no
// lockout, no provisioning window on this path — the daemon listens
// only on the FunctionFS endpoints, never on any network interface.
// Anyone holding the board and a USB cable can control it; that is
// the point, and it matches how USB hardware works. The setup code,
// the owner record, and the lockout stay for BLE only (see gatt.go).
//
// The daemon owns the UDC bind: setup-usb-gadget.sh creates the
// gadget (including the ffs.usb0 function) but does NOT bind the UDC.
// This transport writes the FunctionFS descriptors to /dev/ffs-usb/ep0
// first, then binds the UDC — descriptors must exist before the host
// enumerates the interface. If the gadget is already bound (daemon
// restart), the descriptor write is skipped and the endpoints are
// opened directly.
//
// Protocol: 4-byte big-endian length prefix + UTF-8 JSON payload,
// max 64 KiB per frame. One op per frame, one framed reply. Ops map
// to the GATT contract (spec/gatt.md) minus Pair — there is no
// pairing step on USB: get_info, scan_wifi, set_wifi, set_vpn,
// get_status, control.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	ffsMount    = "/dev/ffs-usb"
	ffsEP0      = ffsMount + "/ep0"
	ffsEP1      = ffsMount + "/ep1" // OUT: host -> device
	ffsEP2      = ffsMount + "/ep2" // IN: device -> host
	gadgetDir   = "/sys/kernel/config/usb_gadget/pi"
	gadgetUDC   = gadgetDir + "/UDC"
	maxUSBFrame = 64 * 1024
)

// --- FunctionFS descriptors (include/uapi/linux/usb/functionfs.h) ---
//
// FUNCTIONFS_DESCRIPTORS_MAGIC = 2, FUNCTIONFS_STRINGS_MAGIC = 3.
// One vendor-specific interface (class 0xFF), two bulk endpoints:
// EP1 OUT + EP2 IN, 512-byte max packet (USB 2.0 high-speed).

func ffsDescriptors() []byte {
	iface := []byte{9, 4, 0, 0, 2, 0xFF, 0, 0, 1} // interface, iInterface=1
	// Full-speed bulk max packet is 64; high-speed bulk max is 512 —
	// the two descriptor sets differ in wMaxPacketSize only.
	epOutFS := []byte{7, 5, 0x01, 2, 0x40, 0x00, 0} // EP1 OUT bulk 64
	epInFS := []byte{7, 5, 0x82, 2, 0x40, 0x00, 0}  // EP2 IN bulk 64
	epOutHS := []byte{7, 5, 0x01, 2, 0x00, 0x02, 0} // EP1 OUT bulk 512
	epInHS := []byte{7, 5, 0x82, 2, 0x00, 0x02, 0}  // EP2 IN bulk 512
	fs := append(append(append([]byte{}, iface...), epOutFS...), epInFS...)
	hs := append(append(append([]byte{}, iface...), epOutHS...), epInHS...)
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(2)) // DESCRIPTORS_MAGIC
	_ = binary.Write(&b, binary.LittleEndian, uint32(24+len(fs)+len(hs)))
	_ = binary.Write(&b, binary.LittleEndian, uint32(3)) // fs_count
	_ = binary.Write(&b, binary.LittleEndian, uint32(3)) // hs_count
	_ = binary.Write(&b, binary.LittleEndian, uint32(0)) // ss_count
	_ = binary.Write(&b, binary.LittleEndian, uint32(0)) // os_count
	b.Write(fs)
	b.Write(hs)
	return b.Bytes()
}

func ffsStrings() []byte {
	// One string (index 1): the interface name the browser picker shows.
	units := utf16.Encode([]rune("HomeSteadyLink"))
	desc := []byte{byte(2 + 2*len(units)), 0x03}
	for _, u := range units {
		desc = append(desc, byte(u), byte(u>>8))
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(3)) // STRINGS_MAGIC
	_ = binary.Write(&b, binary.LittleEndian, uint32(12+len(desc)))
	_ = binary.Write(&b, binary.LittleEndian, uint16(0x0409))
	_ = binary.Write(&b, binary.LittleEndian, uint16(1)) // count
	b.Write(desc)
	return b.Bytes()
}

func gadgetBound() bool {
	b, err := os.ReadFile(gadgetUDC)
	return err == nil && strings.TrimSpace(string(b)) != ""
}

func bindUDC() error {
	udcs, _ := filepath.Glob("/sys/class/udc/*")
	if len(udcs) == 0 {
		return fmt.Errorf("no UDC found under /sys/class/udc")
	}
	udc := filepath.Base(udcs[0])
	if b, err := os.ReadFile(gadgetUDC); err == nil && strings.TrimSpace(string(b)) == udc {
		return nil // already bound to this UDC
	}
	if err := os.WriteFile(gadgetUDC, []byte(udc), 0o644); err != nil {
		return fmt.Errorf("bind UDC %s: %w", udc, err)
	}
	log.Printf("usb: gadget bound to UDC %s", udc)
	return nil
}

// --- Framing ---

func usbReadFrame(f *os.File) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr)
	if n == 0 || n > maxUSBFrame {
		return nil, fmt.Errorf("bad frame length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(f, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func usbWriteFrame(f *os.File, payload []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(payload)))
	if _, err := f.Write(hdr); err != nil {
		return err
	}
	_, err := f.Write(payload)
	return err
}

// --- Dispatcher (trusted transport: no owner check) ---

func usbErr(code, detail string) []byte {
	b, _ := json.Marshal(map[string]string{"error": code, "detail": detail})
	return b
}

func usbOK(extra map[string]interface{}) []byte {
	m := map[string]interface{}{"ok": true}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func usbDispatch(payload []byte) []byte {
	var req struct {
		Op  string `json:"op"`
		Cmd string `json:"cmd"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return usbErr("invalid_json", "request is not JSON")
	}
	switch req.Op {
	case "get_info":
		b, _ := json.Marshal(map[string]string{
			"model": modelName, "serial": identity.Serial,
			"fw": fwVersion, "state": store.get().State,
		})
		return b
	case "get_status":
		return store.json()
	case "scan_wifi":
		if isTxActive() {
			store.update(func(st *State) { st.Error = "busy" })
			return usbErr("busy", "a join/VPN transaction is in progress")
		}
		if apModeOn() {
			store.update(func(st *State) { st.Error = "busy" })
			return usbErr("busy", "AP mode is active")
		}
		if store.get().State == "idle" {
			store.set("scanning", "")
		}
		results := scanWifi() // synchronous, up to 15 s
		if store.get().State == "scanning" {
			store.set("idle", "")
		}
		if results == nil {
			results = []ScanResult{}
		}
		b, _ := json.Marshal(map[string]interface{}{"networks": results})
		return b
	case "set_wifi":
		p, code := validateWifiPayload(payload)
		if code != "" {
			store.update(func(st *State) { st.Error = code })
			return usbErr(code, "Wi-Fi config invalid")
		}
		if securityClass(*p) == "eap" {
			store.set("idle", "unsupported_eap")
			return usbErr("unsupported_eap", "EAP networks are not supported")
		}
		go runWifiTransaction(p)
		return usbOK(nil)
	case "set_vpn":
		if _, code := stageVpnConfig(payload); code != "" {
			store.update(func(st *State) { st.Error = code })
			return usbErr(code, "VPN config invalid")
		}
		if isTxActive() {
			log.Printf("usb: VpnConfig staged in candidate/ for the running transaction's VPN phase")
		} else {
			commitStagedVpnNow()
		}
		return usbOK(nil)
	case "control":
		if !knownControlCmd(req.Cmd) {
			return usbErr("unknown_cmd", "unknown control command")
		}
		// doControl, not handleControl: no owner check on the USB
		// path — physical possession is the trust root.
		go doControl(req.Cmd, nil)
		return usbOK(nil)
	default:
		return usbErr("unknown_op", "unknown op: "+req.Op)
	}
}

// --- Server ---

type usbServer struct {
	mu sync.Mutex // serializes replies on the single bulk-IN endpoint
}

func (s *usbServer) serve() {
	// Wait for the gadget script to create the FunctionFS mount.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(ffsEP0); err == nil {
			break
		}
		if time.Now().After(deadline) {
			log.Printf("usb: %s never appeared (usb-gadget.service did not mount FunctionFS); USB transport disabled", ffsEP0)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	// First boot of this daemon: write descriptors, then bind the UDC.
	// On a daemon restart the gadget is already bound — skip the
	// descriptor write (FunctionFS rejects it once bound).
	if !gadgetBound() {
		ep0, err := os.OpenFile(ffsEP0, os.O_RDWR, 0)
		if err != nil {
			log.Printf("usb: open %s: %v; USB transport disabled", ffsEP0, err)
			return
		}
		// ep0 stays open for the daemon's lifetime (control requests
		// arrive on it); the descriptors persist once written.
		defer ep0.Close()
		if _, err := ep0.Write(ffsDescriptors()); err != nil {
			log.Printf("usb: write descriptors: %v; USB transport disabled", err)
			return
		}
		if _, err := ep0.Write(ffsStrings()); err != nil {
			log.Printf("usb: write strings: %v; USB transport disabled", err)
			return
		}
		if err := bindUDC(); err != nil {
			log.Printf("usb: %v; USB transport disabled", err)
			return
		}
	} else {
		log.Printf("usb: gadget already bound — skipping descriptor write (daemon restart)")
	}
	log.Printf("usb: FunctionFS transport up (vendor interface, class 0xFF)")

	for {
		out, err := os.OpenFile(ffsEP1, os.O_RDWR, 0)
		if err != nil {
			log.Printf("usb: open %s: %v (retry in 1s)", ffsEP1, err)
			time.Sleep(time.Second)
			continue
		}
		in, err := os.OpenFile(ffsEP2, os.O_RDWR, 0)
		if err != nil {
			log.Printf("usb: open %s: %v (retry in 1s)", ffsEP2, err)
			out.Close()
			time.Sleep(time.Second)
			continue
		}
		log.Printf("usb: endpoints open, serving requests")
		for {
			payload, err := usbReadFrame(out)
			if err != nil {
				log.Printf("usb: read error (%v) — reopening endpoints", err)
				break
			}
			// One worker per request; replies are serialized on the
			// single bulk-IN endpoint. The page sends one request at
			// a time, but a slow scan must not block status polls.
			go func(p []byte) {
				reply := usbDispatch(p)
				s.mu.Lock()
				_ = usbWriteFrame(in, reply)
				s.mu.Unlock()
			}(payload)
		}
		out.Close()
		in.Close()
		time.Sleep(time.Second)
	}
}

func startUSB() {
	s := &usbServer{}
	go s.serve()
}
