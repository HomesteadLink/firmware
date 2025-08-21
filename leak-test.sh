#!/usr/bin/env bash
# leak-test.sh — Consolidated IPv4/IPv6 DNS and egress leak checks (macOS-friendly)
#
# Features
# - Resolver check (dig) to detect DNS leak vs expected router DNS (default 192.168.64.1)
# - IPv4 egress via DNS-only (OpenDNS/Google) and via HTTPS API (ifconfig.co/json over IPv4)
# - IPv6 egress test via HTTPS API (ifconfig.co/json over IPv6)
#   • If IPv6 is disabled/unavailable, treated as OK (no leak)
# - Country checks (Team Cymru + countries.nerd.dk for IPv4; ifconfig.co country_iso for v4/v6)
# - Clear summary and exit codes: 0 OK, 2 potential leak
#
# Usage
#   bash leak-test.sh [--expect-dns 192.168.64.1] [--expect-country US]
#   EXPECT_DNS=192.168.64.1 EXPECT_COUNTRY=US bash leak-test.sh
#
# Notes
# - macOS ships dig and curl by default. No jq required.
# - Country is approximate (based on egress IP GeoIP). VPN/exit-nodes affect results.

set -euo pipefail

EXPECT_DNS="${EXPECT_DNS:-192.168.64.1}"
EXPECT_COUNTRY="${EXPECT_COUNTRY:-}"
ROUTER_DNS="$EXPECT_DNS"
TIMEOUT="3"
CURL_MAXTIME="4"

# Colors (TTY only)
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

usage() {
  cat <<EOF
Leak test (IPv4/IPv6, DNS + HTTPS IPv4/IPv6)

Options:
  --expect-dns IP        Expected local DNS resolver (default: 192.168.64.1)
  --expect-country CC    Expected ISO country code (optional)
  -h, --help             Show help
EOF
}

while [ "${1:-}" != "" ]; do
  case "$1" in
    --expect-dns) shift; EXPECT_DNS="${1:-}"; ROUTER_DNS="$EXPECT_DNS" ;;
    --expect-country) shift; EXPECT_COUNTRY="${1:-}" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
  shift || true
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dig
need awk
need tr
need curl

hr() { printf '%*s\n' "${1:-60}" '' | tr ' ' '-'; }

# Wrapper for dig with timeouts
digx() { dig +time=$TIMEOUT +tries=1 "$@"; }

# Resolver used by dig (SERVER line)
resolver_used() {
  local out server_line server_ip
  out=$(digx +noall +answer +stats example.com || true)
  server_line=$(printf "%s\n" "$out" | awk '/^;; SERVER: /{print; exit}')
  server_ip=$(printf "%s\n" "$server_line" | awk -F ' ' '{print $3}' | awk -F '#' '{print $1}')
  printf "%s\n" "$server_ip"
}

# Public IPv4 via DNS-only
ipv4_public_dns() {
  local ip
  ip=$(digx +short myip.opendns.com @resolver1.opendns.com | tail -n1 || true)
  if ! printf "%s" "$ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    ip=$(digx +short TXT o-o.myaddr.l.google.com @ns1.google.com | tr -d '"' | tail -n1 || true)
  fi
  printf "%s\n" "$ip"
}

# Team Cymru (txt line and country only)
ipv4_cymru_line() { digx +short -t txt "$1".origin.asn.cymru.com | tr -d '"'; }
ipv4_cymru_cc()   { ipv4_cymru_line "$1" | awk -F'|' '{gsub(/ /,"",$0); print $4}'; }
ipv4_nerddk_cc()  { digx +short "$1".country.zz.countries.nerd.dk | tr -d '"'; }

# CHAOS TXT from router (dnsmasq often responds)
dnsmasq_chaos() {
  local h v
  h=$(digx +short CHAOS TXT hostname.bind @"$ROUTER_DNS" 2>/dev/null | tr -d '"' || true)
  v=$(digx +short CHAOS TXT version.bind  @"$ROUTER_DNS" 2>/dev/null | tr -d '"' || true)
  printf "%s | %s\n" "${h:-?}" "${v:-?}"
}

# Cloudflare/OpenDNS hints
cf_pop() { local a b; a=$(digx +short CHAOS TXT id.server @1.1.1.1 | tr -d '"'); b=$(digx +short CHAOS TXT id.server @1.0.0.1 | tr -d '"'); printf "%s | %s\n" "${a:-?}" "${b:-?}"; }
odns_dbg() { digx +short TXT debug.opendns.com @resolver1.opendns.com | tr -d '"'; }

# ifconfig.co/json helpers (no jq)
json_field() { # json_field <key> ; reads JSON on stdin, extracts first string value for key
  local key="$1"
  sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^"]*\)\".*/\1/p" | head -n1
}

ifconfig_v4() { curl -4 -fsS --max-time "$CURL_MAXTIME" https://ifconfig.co/json 2>/dev/null || true; }
ifconfig_v6() { curl -6 -fsS --max-time "$CURL_MAXTIME" https://ifconfig.co/json 2>/dev/null || true; }

main() {
  echo -e "${CYAN}Consolidated Leak Test (IPv4/IPv6)${NC}"
  hr 60
  echo "Expected router DNS: $ROUTER_DNS"
  [ -n "$EXPECT_COUNTRY" ] && echo "Expected egress country: $EXPECT_COUNTRY"
  echo

  # [1] Resolver check
  echo "[1/6] DNS resolver used by this host (dig stats)"
  local used_resolver leak_dns=0
  used_resolver=$(resolver_used)
  echo "Resolver used: ${used_resolver:-unknown}"
  if [ -n "$used_resolver" ] && [ -n "$ROUTER_DNS" ] && [ "$used_resolver" != "$ROUTER_DNS" ]; then
    echo -e "${RED}WARNING:${NC} Queries appear to bypass $ROUTER_DNS"
    leak_dns=1
  else
    echo -e "${GREEN}OK:${NC} Resolver matches expected (or unknown)"
  fi
  echo

  # [2] Router CHAOS TXT
  echo "[2/6] Router CHAOS TXT (dnsmasq hint)"
  echo "CHAOS @${ROUTER_DNS}: $(dnsmasq_chaos)"
  echo

  # [3] IPv4 egress via DNS-only + Geo
  echo "[3/6] IPv4 public IP via DNS-only and Geo"
  local v4_ip v4_cymru v4_cc_cymru v4_cc_nerd
  v4_ip=$(ipv4_public_dns)
  if printf "%s" "$v4_ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    echo "IPv4 (DNS): $v4_ip"
    v4_cymru=$(ipv4_cymru_line "$v4_ip")
    v4_cc_cymru=$(ipv4_cymru_cc "$v4_ip")
    v4_cc_nerd=$(ipv4_nerddk_cc "$v4_ip")
    echo "Team Cymru: ${v4_cymru:-n/a}"
    echo "Country (Cymru): ${v4_cc_cymru:-n/a}"
    echo "Country (nerd.dk): ${v4_cc_nerd:-n/a}"
  else
    echo -e "${YELLOW}NOTE:${NC} Could not obtain IPv4 via DNS-only"
  fi
  echo

  # [4] IPv4 via HTTPS API (ifconfig.co/json)
  echo "[4/6] IPv4 egress via ifconfig.co/json"
  local v4_json v4_api_ip v4_api_cc
  v4_json=$(ifconfig_v4)
  if [ -n "$v4_json" ]; then
    v4_api_ip=$(printf "%s" "$v4_json" | json_field ip)
    v4_api_cc=$(printf "%s" "$v4_json" | json_field country_iso)
    echo "IPv4 API IP: ${v4_api_ip:-n/a}"
    echo "IPv4 API Country: ${v4_api_cc:-n/a}"
  else
    echo -e "${YELLOW}NOTE:${NC} IPv4 API request failed"
  fi
  echo

  # [5] IPv6 egress via ifconfig.co/json (treat unavailable as OK)
  echo "[5/6] IPv6 egress (ifconfig.co/json over IPv6)"
  local v6_json v6_api_ip v6_api_cc v6_available=0
  v6_json=$(ifconfig_v6)
  if [ -n "$v6_json" ]; then
    v6_api_ip=$(printf "%s" "$v6_json" | json_field ip)
    v6_api_cc=$(printf "%s" "$v6_json" | json_field country_iso)
    if [ -n "$v6_api_ip" ]; then v6_available=1; fi
    echo "IPv6 API IP: ${v6_api_ip:-n/a}"
    echo "IPv6 API Country: ${v6_api_cc:-n/a}"
  else
    echo "IPv6 appears unavailable (no response over v6) — treated as OK"
  fi
  echo

  # [6] Resolver POP hints
  echo "[6/6] Resolver POP hints"
  echo "Cloudflare id.server @1.1.1.1 | @1.0.0.1: $(cf_pop)"
  echo "OpenDNS debug: $(odns_dbg)"
  echo

  # Summary
  hr 60
  echo "Summary:"
  echo "  Resolver used: ${used_resolver:-unknown} (expected: $ROUTER_DNS)"
  [ -n "${v4_ip:-}" ] && echo "  IPv4 (DNS) IP: $v4_ip | CC: ${v4_cc_cymru:-?}/${v4_cc_nerd:-?}"
  [ -n "${v4_api_ip:-}" ] && echo "  IPv4 (API) IP: $v4_api_ip | CC: ${v4_api_cc:-?}"
  if [ "$v6_available" -eq 1 ]; then
    echo "  IPv6 (API) IP: ${v6_api_ip:-?} | CC: ${v6_api_cc:-?}"
  else
    echo "  IPv6: unavailable/disabled (OK)"
  fi
  [ -n "$EXPECT_COUNTRY" ] && echo "  Expected country: $EXPECT_COUNTRY"

  local exit_code=0
  # DNS leak if resolver bypasses router
  if [ "$leak_dns" -eq 1 ]; then exit_code=2; fi

  # Country mismatch checks (if EXPECT_COUNTRY provided)
  if [ -n "$EXPECT_COUNTRY" ]; then
    # Consider a mismatch only if both independent sources (Cymru & nerd.dk) disagree
    if [ -n "${v4_cc_cymru:-}" ] || [ -n "${v4_cc_nerd:-}" ]; then
      if [ "${v4_cc_cymru:-X}" != "$EXPECT_COUNTRY" ] && [ "${v4_cc_nerd:-X}" != "$EXPECT_COUNTRY" ]; then
        echo -e "${YELLOW}NOTE:${NC} IPv4 egress country differs from expectation"
      fi
    fi
    # IPv6: only enforce if IPv6 is actually available
    if [ "$v6_available" -eq 1 ] && [ -n "${v6_api_cc:-}" ] && [ "$v6_api_cc" != "$EXPECT_COUNTRY" ]; then
      echo -e "${RED}WARNING:${NC} IPv6 egress country differs from expectation — possible IPv6 leak"
      exit_code=2
    fi
  fi

  if [ "$exit_code" -eq 0 ]; then
    echo -e "${GREEN}No leaks detected${NC} (resolver OK; IPv6 disabled or matches expectations)"
  else
    echo -e "${RED}Potential leak detected${NC} — see warnings above"
  fi
  exit "$exit_code"
}

main "$@"
