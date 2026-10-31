#!/usr/bin/env python3
"""Minimal FDT tools for the HomeSteadyLink image build (no dtc on the
build host): build the bt-uart overlay blob, apply an overlay to a
base DTB in memory, and assert the merged tree (§F2 hard gate).

Usage:
  fdt_tools.py make-overlay BASE.dtb OUT.dtbo
  fdt_tools.py assert BASE.dtb OVERLAY.dtbo   (merged-tree assertion)
Only the shapes this build needs are supported.
"""
import struct
import sys

FDT_MAGIC = 0xD00DFEED
BEGIN, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9

BT_COMPATIBLE = "allwinner,sunxi-btlpm"  # vendor (Xunlong) DTS, see bt-uart.dts
UART1_PATH = "/soc/serial@5000400"


class Node:
    def __init__(self, name=""):
        self.name = name
        self.props = {}      # name -> bytes
        self.children = {}   # name -> Node

    def find(self, path):
        node = self
        for part in [p for p in path.split("/") if p]:
            node = node.children.get(part)
            if node is None:
                return None
        return node


def parse_fdt(data):
    magic, total, off_struct, off_strings, _rsv, _ver, _lver, _cpuid, size_strings, size_struct = struct.unpack_from(">10I", data, 0)
    if magic != FDT_MAGIC:
        raise ValueError("bad FDT magic")
    strings = data[off_strings:off_strings + size_strings]
    struct_block = data[off_struct:off_struct + size_struct]

    def cstr(buf, off):
        end = buf.index(b"\x00", off)
        return buf[off:end].decode("utf-8", "replace")

    root = Node("")
    stack = [root]
    first = True
    pos = 0
    while pos < len(struct_block):
        (token,) = struct.unpack_from(">I", struct_block, pos)
        pos += 4
        if token == BEGIN:
            end = struct_block.index(b"\x00", pos)
            name = struct_block[pos:end].decode("utf-8", "replace")
            pos = (end + 4) & ~3
            if first:  # the first BEGIN_NODE is the root itself
                first = False
                root.name = name
                stack.append(root)
                continue
            node = Node(name)
            stack[-1].children[name] = node
            stack.append(node)
        elif token == END_NODE:
            stack.pop()
        elif token == PROP:
            plen, nameoff = struct.unpack_from(">II", struct_block, pos)
            pos += 8
            val = struct_block[pos:pos + plen]
            pos = (pos + plen + 3) & ~3
            stack[-1].props[cstr(strings, nameoff)] = val
        elif token == NOP:
            continue
        elif token == END:
            break
    return root


def prop_str(node, name):
    v = node.props.get(name)
    if v is None:
        return None
    return v.split(b"\x00")[0].decode("utf-8", "replace")


def node_phandle(node):
    for key in ("phandle", "linux,phandle"):
        if key in node.props and len(node.props[key]) == 4:
            return struct.unpack(">I", node.props[key])[0]
    return None


def symbols(root):
    sym = root.children.get("__symbols__")
    out = {}
    if sym:
        for label, val in sym.props.items():
            out[label] = val.split(b"\x00")[0].decode()
    return out


def find_by_phandle(root, phandle):
    if node_phandle(root) == phandle:
        return root
    for child in root.children.values():
        hit = find_by_phandle(child, phandle)
        if hit is not None:
            return hit
    return None


# --- FDT writer (for the overlay blob) ---

class Writer:
    def __init__(self):
        self.struct = bytearray()
        self.strings = bytearray()
        self.string_offsets = {}

    def string_off(self, s):
        if s not in self.string_offsets:
            self.string_offsets[s] = len(self.strings)
            self.strings += s.encode() + b"\x00"
        return self.string_offsets[s]

    def token(self, t):
        self.struct += struct.pack(">I", t)

    def prop(self, name, value):
        self.token(PROP)
        self.struct += struct.pack(">II", len(value), self.string_off(name))
        self.struct += value
        while len(self.struct) % 4:
            self.struct += b"\x00"

    def begin(self, name):
        self.token(BEGIN)
        self.struct += name.encode() + b"\x00"
        while len(self.struct) % 4:
            self.struct += b"\x00"

    def end_node(self):
        self.token(END_NODE)

    def blob(self):
        self.token(END)
        header_size = 40
        rsv_size = 16
        off_struct = header_size + rsv_size
        off_strings = off_struct + len(self.struct)
        total = off_strings + len(self.strings)
        header = struct.pack(">10I", FDT_MAGIC, total, off_struct, off_strings,
                             header_size, 17, 16, 0, len(self.strings), len(self.struct))
        return header + b"\x00" * rsv_size + bytes(self.struct) + bytes(self.strings)


def u32(n):
    return struct.pack(">I", n)


def cstring(s):
    return s.encode() + b"\x00"


def make_overlay(base):
    sym = symbols(base)
    uart1_path = sym.get("uart1", UART1_PATH)
    uart1 = base.find(uart1_path)
    if uart1 is None:
        raise SystemExit("base DTB has no uart1 node at " + uart1_path)
    uart1_ph = node_phandle(uart1)
    if uart1_ph is None:
        raise SystemExit("uart1 node has no phandle in base DTB")
    pins_path = sym.get("uart1_pins")
    pins = base.find(pins_path) if pins_path else None
    pins_ph = node_phandle(pins) if pins else None

    w = Writer()
    w.begin("")
    w.prop("compatible", cstring("allwinner,sun50i-h616") + cstring("allwinner,sun50i-h618"))
    w.begin("fragment@0")
    w.prop("target", u32(uart1_ph))
    w.begin("__overlay__")
    w.prop("status", cstring("okay"))
    if pins_ph is not None:
        w.prop("pinctrl-names", cstring("default"))
        w.prop("pinctrl-0", u32(pins_ph))
    w.begin("bluetooth")
    w.prop("compatible", cstring(BT_COMPATIBLE))
    w.prop("status", cstring("okay"))
    w.end_node()
    w.end_node()
    w.end_node()
    w.begin("fragment@1")
    w.prop("target-path", cstring("/aliases"))
    w.begin("__overlay__")
    w.prop("serial1", cstring(UART1_PATH))
    w.end_node()
    w.end_node()
    w.end_node()
    return w.blob()


def merge_into(dst, src):
    for k, v in src.props.items():
        dst.props[k] = v
    for name, child in src.children.items():
        if name in dst.children:
            merge_into(dst.children[name], child)
        else:
            dst.children[name] = child


def apply_overlay(base, overlay):
    for frag_name, frag in overlay.children.items():
        if not frag_name.startswith("fragment"):
            continue
        ov = frag.children.get("__overlay__")
        if ov is None:
            continue
        target = None
        if "target" in frag.props and len(frag.props["target"]) == 4:
            (ph,) = struct.unpack(">I", frag.props["target"])
            target = find_by_phandle(base, ph)
        if target is None and "target-path" in frag.props:
            target = base.find(prop_str(frag, "target-path"))
        if target is None and "target-path" in frag.props:
            # /aliases may not exist as a child in parsed form under root
            target = base.children.get("aliases")
        if target is None:
            raise SystemExit("overlay fragment target not found: " + frag_name)
        merge_into(target, ov)
    return base


def assert_merged(base):
    uart1 = base.find(UART1_PATH)
    if uart1 is None:
        return "FAIL: no %s node" % UART1_PATH
    if prop_str(uart1, "status") not in ("okay", "ok"):
        return "FAIL: uart1 status=%r (not enabled)" % prop_str(uart1, "status")
    bt = uart1.children.get("bluetooth")
    if bt is None:
        return "FAIL: uart1 has no bluetooth child node"
    if prop_str(bt, "status") not in ("okay", "ok", None):
        return "FAIL: bluetooth node status=%r" % prop_str(bt, "status")
    if BT_COMPATIBLE not in (prop_str(bt, "compatible") or ""):
        return "FAIL: bluetooth compatible=%r, want %s" % (prop_str(bt, "compatible"), BT_COMPATIBLE)
    aliases = base.children.get("aliases")
    if aliases is not None and prop_str(aliases, "serial1") != UART1_PATH:
        return "FAIL: aliases serial1=%r" % prop_str(aliases, "serial1")
    return "PASS"


USB_FRAGMENTS = (
    # (symbol, props) — mirrors boards/orangepizero2w/usb0-device.dts,
    # written by the board plugin's board_apply_dts_overlay().
    ("usbotg", (("dr_mode", "peripheral"), ("status", "okay"))),
    ("usbphy", (("status", "okay"),)),
    ("ehci0", (("status", "disabled"),)),
    ("ohci0", (("status", "disabled"),)),
)


def make_usb_overlay(base):
    sym = symbols(base)
    w = Writer()
    w.begin("")
    w.prop("compatible", cstring("allwinner,sun50i-h616") + cstring("allwinner,sun50i-h618"))
    for i, (label, props) in enumerate(USB_FRAGMENTS):
        path = sym.get(label)
        node = base.find(path) if path else None
        if node is None:
            raise SystemExit("base DTB has no %s node (%s)" % (label, path))
        ph = node_phandle(node)
        if ph is None:
            raise SystemExit("%s node has no phandle in base DTB" % label)
        w.begin("fragment@%d" % i)
        w.prop("target", u32(ph))
        w.begin("__overlay__")
        for name, val in props:
            w.prop(name, cstring(val))
        w.end_node()
        w.end_node()
    return w.blob()


def assert_usb_merged(base):
    sym = symbols(base)
    for label, props in USB_FRAGMENTS:
        path = sym.get(label)
        node = base.find(path) if path else None
        if node is None:
            return "FAIL: no %s node (%s)" % (label, path)
        for name, want in props:
            got = prop_str(node, name)
            if got != want:
                return "FAIL: %s %s=%r, want %r" % (label, name, got, want)
    return "PASS"


def main(argv):
    if argv[1] == "make-usb-overlay":
        base = parse_fdt(open(argv[2], "rb").read())
        open(argv[3], "wb").write(make_usb_overlay(base))
        print("usb overlay written:", argv[3])
        return 0
    if argv[1] == "assert-usb":
        base = parse_fdt(open(argv[2], "rb").read())
        overlay = parse_fdt(open(argv[3], "rb").read())
        merged = apply_overlay(base, overlay)
        result = assert_usb_merged(merged)
        print("merged-DT usb assertion (§F1 gadget):", result)
        return 0 if result == "PASS" else 1
    if argv[1] == "make-overlay":
        base = parse_fdt(open(argv[2], "rb").read())
        open(argv[3], "wb").write(make_overlay(base))
        print("overlay written:", argv[3])
        return 0
    if argv[1] == "assert":
        base = parse_fdt(open(argv[2], "rb").read())
        overlay = parse_fdt(open(argv[3], "rb").read())
        merged = apply_overlay(base, overlay)
        result = assert_merged(merged)
        print("merged-DT assertion (§F2):", result)
        return 0 if result == "PASS" else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
