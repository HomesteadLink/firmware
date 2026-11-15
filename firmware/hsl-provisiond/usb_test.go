package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
)

// Descriptor blob layout (include/uapi/linux/usb/functionfs.h):
// head magic=2, length=70, fs_count=3, hs_count=3, ss=0, os=0;
// one interface (class 0xFF) + EP1 OUT bulk + EP2 IN bulk, one set
// per speed (FS max packet 64, HS max packet 512).
func TestFFSDescriptors(t *testing.T) {
	d := ffsDescriptors()
	if len(d) != 70 {
		t.Fatalf("descriptors len = %d, want 70", len(d))
	}
	le := binary.LittleEndian
	if got := le.Uint32(d[0:4]); got != 2 {
		t.Fatalf("magic = %d, want 2", got)
	}
	if got := le.Uint32(d[4:8]); got != 70 {
		t.Fatalf("length = %d, want 70", got)
	}
	if got := le.Uint32(d[8:12]); got != 3 {
		t.Fatalf("fs_count = %d, want 3", got)
	}
	if got := le.Uint32(d[12:16]); got != 3 {
		t.Fatalf("hs_count = %d, want 3", got)
	}
	fs := d[24:47]
	if fs[0] != 9 || fs[1] != 4 || fs[5] != 0xFF {
		t.Fatalf("interface descriptor = %v, want class 0xFF", fs[:9])
	}
	if fs[9] != 7 || fs[10] != 5 || fs[11] != 0x01 || fs[12] != 2 {
		t.Fatalf("EP OUT descriptor = %v", fs[9:16])
	}
	if got := le.Uint16(fs[13:15]); got != 64 {
		t.Fatalf("FS EP OUT max packet = %d, want 64", got)
	}
	if fs[16] != 7 || fs[17] != 5 || fs[18] != 0x82 || fs[19] != 2 {
		t.Fatalf("EP IN descriptor = %v", fs[16:23])
	}
	if got := le.Uint16(fs[20:22]); got != 64 {
		t.Fatalf("FS EP IN max packet = %d, want 64", got)
	}
	hs := d[47:70]
	if got := le.Uint16(hs[13:15]); got != 512 {
		t.Fatalf("HS EP OUT max packet = %d, want 512", got)
	}
	if got := le.Uint16(hs[20:22]); got != 512 {
		t.Fatalf("HS EP IN max packet = %d, want 512", got)
	}
}

func TestFFSStrings(t *testing.T) {
	s := ffsStrings()
	le := binary.LittleEndian
	if got := le.Uint32(s[0:4]); got != 3 {
		t.Fatalf("magic = %d, want 3", got)
	}
	if got := le.Uint32(s[4:8]); got != uint32(len(s)) {
		t.Fatalf("length = %d, want %d", got, len(s))
	}
	if got := le.Uint16(s[8:10]); got != 0x0409 {
		t.Fatalf("code = %#x, want 0x0409", got)
	}
	if got := le.Uint16(s[10:12]); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
	// String descriptor: bLength, 0x03, "HomeSteadyLink" UTF-16LE
	// (14 chars -> 2 + 2*14 = 30 bytes).
	if s[12] != 30 || s[13] != 0x03 {
		t.Fatalf("string header = [%d %d], want [30 3]", s[12], s[13])
	}
	units := make([]uint16, 14)
	for i := range units {
		units[i] = le.Uint16(s[14+2*i : 16+2*i])
	}
	var runes []rune
	for _, u := range units {
		runes = append(runes, rune(u))
	}
	if string(runes) != "HomeSteadyLink" {
		t.Fatalf("string = %q, want HomeSteadyLink", string(runes))
	}
}

func TestUSBFrameRoundTrip(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	want := []byte(`{"op":"get_info"}`)
	if err := usbWriteFrame(w, want); err != nil {
		t.Fatal(err)
	}
	got, err := usbReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip = %q, want %q", got, want)
	}
}

func TestUSBDispatch(t *testing.T) {
	var m map[string]interface{}
	// Unknown op.
	if err := json.Unmarshal(usbDispatch([]byte(`{"op":"nope"}`)), &m); err != nil {
		t.Fatal(err)
	}
	if m["error"] != "unknown_op" {
		t.Fatalf("unknown op reply = %v", m)
	}
	// Invalid JSON.
	if err := json.Unmarshal(usbDispatch([]byte(`{oops`)), &m); err != nil {
		t.Fatal(err)
	}
	if m["error"] != "invalid_json" {
		t.Fatalf("invalid JSON reply = %v", m)
	}
	// get_info: no setup code, no owner — answers directly.
	if err := json.Unmarshal(usbDispatch([]byte(`{"op":"get_info"}`)), &m); err != nil {
		t.Fatal(err)
	}
	if m["model"] != modelName {
		t.Fatalf("get_info reply = %v", m)
	}
	// get_status.
	if err := json.Unmarshal(usbDispatch([]byte(`{"op":"get_status"}`)), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["state"]; !ok {
		t.Fatalf("get_status reply = %v", m)
	}
	// Unknown control command is rejected synchronously.
	if err := json.Unmarshal(usbDispatch([]byte(`{"op":"control","cmd":"explode"}`)), &m); err != nil {
		t.Fatal(err)
	}
	if m["error"] != "unknown_cmd" {
		t.Fatalf("unknown cmd reply = %v", m)
	}
	// Invalid Wi-Fi payload is rejected synchronously.
	if err := json.Unmarshal(usbDispatch([]byte(`{"op":"set_wifi","ssid":""}`)), &m); err != nil {
		t.Fatal(err)
	}
	if m["error"] != "wifi_config_invalid" {
		t.Fatalf("bad wifi reply = %v", m)
	}
}
