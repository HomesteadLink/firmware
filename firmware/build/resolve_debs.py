#!/usr/bin/env python3
"""Resolve + download arm64 .debs for the debugfs image build (§F1/F6).

Sources: Ubuntu noble ports (main+universe) and the Tailscale stable
repo. Dependency closure is computed from the Packages indices;
packages already installed in the stock image (per --stock-status)
are skipped. Downloads land in --out-dir; the plan is printed.

Usage:
  resolve_debs.py --stock-status FILE --out-dir DIR pkg [pkg...]
  resolve_debs.py --tailscale-url   (print newest tailscale deb URL)
"""
import gzip
import io
import re
import subprocess
import sys
import urllib.request

UBUNTU = "http://ports.ubuntu.com/ubuntu-ports"
SUITES = [("noble", "main"), ("noble", "universe"),
          ("noble-updates", "main"), ("noble-updates", "universe")]
TS_BASE = "https://pkgs.tailscale.com/stable/ubuntu"
TS_INDEX = TS_BASE + "/dists/noble/main/binary-arm64/Packages"


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def parse_packages(data):
    pkgs = {}
    for stanza in data.decode("utf-8", "replace").split("\n\n"):
        stanza = stanza.strip()
        if not stanza:
            continue
        fields = {}
        key = None
        for line in stanza.split("\n"):
            if line.startswith((" ", "\t")) and key:
                fields[key] += "\n" + line.strip()
            elif ":" in line:
                key, val = line.split(":", 1)
                fields[key.strip()] = val.strip()
        name = fields.get("Package")
        if name:
            # keep the highest version seen (simple lexical max is
            # wrong in general; suites are ordered so later wins)
            pkgs[name] = fields
    return pkgs


def load_index():
    index = {}
    for suite, comp in SUITES:
        url = f"{UBUNTU}/dists/{suite}/{comp}/binary-arm64/Packages.gz"
        try:
            raw = gzip.decompress(fetch(url))
        except Exception as e:
            print(f"WARN: cannot fetch {url}: {e}", file=sys.stderr)
            continue
        for name, fields in parse_packages(raw).items():
            fields["_base"] = f"{UBUNTU}/"
            index[name] = fields
    return index


def load_tailscale():
    raw = fetch(TS_INDEX)
    versions = {}
    for stanza in raw.decode("utf-8", "replace").split("\n\n"):
        if "Package: tailscale" in stanza:
            fields = {}
            for line in stanza.split("\n"):
                if ":" in line and not line.startswith(" "):
                    k, v = line.split(":", 1)
                    fields[k.strip()] = v.strip()
            versions[fields.get("Version", "")] = fields
    if not versions:
        raise SystemExit("no tailscale in repo index")
    def vkey(v):
        return [int(x) for x in re.findall(r"\d+", v)]
    best = max(versions, key=vkey)
    fields = versions[best]
    fields["_base"] = TS_BASE + "/"
    return {"tailscale": fields}


def dep_names(depends):
    names = []
    for group in (depends or "").split(","):
        group = group.strip()
        if not group:
            continue
        alt = group.split("|")[0].strip()
        alt = re.split(r"\s|\(", alt)[0]
        if alt:
            names.append(alt)
    return names


def main():
    args = sys.argv[1:]
    if "--tailscale-url" in args:
        ts = load_tailscale()["tailscale"]
        print(ts["_base"] + ts["Filename"])
        return 0
    stock_path = args[args.index("--stock-status") + 1]
    out_dir = args[args.index("--out-dir") + 1]
    want = [a for a in args if not a.startswith("--")
            and a not in (stock_path, out_dir)]
    stock = set()
    try:
        for line in open(stock_path):
            if line.startswith("Package: "):
                stock.add(line.split(":", 1)[1].strip())
    except FileNotFoundError:
        pass
    index = load_index()
    index.update(load_tailscale())
    # virtual packages provided by stock (e.g. awk) satisfy deps
    provides = set()
    try:
        cur = None
        for line in open(stock_path):
            if line.startswith("Package: "):
                cur = line.split(":", 1)[1].strip()
            if line.startswith("Provides: ") and cur:
                for p in line.split(":", 1)[1].split(","):
                    provides.add(re.split(r"\s|\(", p.strip())[0])
    except FileNotFoundError:
        pass

    queue = list(want)
    chosen = {}
    seen = set()
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        if name in stock or name in provides:
            print(f"skip {name}: already in stock image")
            continue
        fields = index.get(name)
        if fields is None:
            # try a provider in the index
            provider = None
            for cand, f in index.items():
                prov = [re.split(r"\s|\(", p.strip())[0]
                        for p in (f.get("Provides") or "").split(",") if p.strip()]
                if name in prov:
                    provider = cand
                    break
            if provider is None:
                raise SystemExit(f"cannot resolve package: {name}")
            print(f"virtual {name} -> {provider}")
            queue.append(provider)
            continue
        chosen[name] = fields
        for dep in dep_names(fields.get("Depends")) + dep_names(fields.get("Pre-Depends")):
            queue.append(dep)
    subprocess.run(["mkdir", "-p", out_dir], check=True)
    for name, fields in sorted(chosen.items()):
        url = fields["_base"] + fields["Filename"]
        dest = f"{out_dir}/{name}.deb"
        print(f"download {name} {fields.get('Version','?')} <- {url}")
        subprocess.run(["curl", "-fsSL", "-o", dest, url], check=True)
    print(f"resolved {len(chosen)} debs: {' '.join(sorted(chosen))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
