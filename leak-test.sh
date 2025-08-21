#!/bin/bash
# leak-test.sh  Consolidated IPv4/IPv6 DNS and egress leak checks (macOS-friendly)
#
# Features
# - Resolver check (dig) to detect DNS leak vs expected router DNS (default 192.168.64.1)
# - IPv4 egress via DNS-only (OpenDNS/Google) and via HTTPS API (ifconfig.co/json over IPv4)
# - IPv6 egress test via HTTPS API (ifconfig.co/json over IPv6)
#    If IPv6 is disabled/unavailable, treated as OK (no leak)
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

# Wrapper for dig with timeouts (never fail hard)
digx() { dig +time=$TIMEOUT +tries=1 "$@" || true; }

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
  if ! printf "%s\n" "$ip" | awk -F. 'NF==4{ok=1; for(i=1;i<=4;i++){ if($i!~/^[0-9]+$/||$i<0||$i>255){ok=0} } } END{exit ok?0:1}'; then
    ip=$(digx +short TXT o-o.myaddr.l.google.com @ns1.google.com | tr -d '"' | tail -n1 || true)
  fi
  printf "%s\n" "$ip"
}

# Team Cymru (txt line and country only)
ipv4_cymru_line() { digx +short -t txt "$1".origin.asn.cymru.com | tr -d '"'; }
ipv4_cymru_cc()   { ipv4_cymru_line "$1" | awk -F'|' '{gsub(/ /,"",$0); print $4}'; }
ipv4_nerddk_cc()  { digx +short "$1".country.zz.countries.nerd.dk | tr -d '"'; }

# GeoIP country lookup: prefers local MaxMind DB via mmdblookup, falls back to HTTP APIs
geo_cc_mmdb() {
  local ip="$1" db cc
  for db in \
    /usr/local/share/GeoIP/GeoLite2-Country.mmdb \
    /usr/share/GeoIP/GeoLite2-Country.mmdb \
    /opt/homebrew/var/GeoIP/GeoLite2-Country.mmdb; do
    [ -r "$db" ] || continue
    cc=$(mmdblookup --file "$db" --ip "$ip" country iso_code 2>/dev/null | awk -F '"' '/"[A-Z][A-Z]"/{print $2; exit}')
    if [ -n "$cc" ]; then printf "%s\n" "$cc"; return 0; fi
  done
  return 1
}

geo_cc_http() {
  local ip="$1" cc
  cc=$(curl -fsS --max-time "$CURL_MAXTIME" "https://ipinfo.io/$ip/country" 2>/dev/null | tr -d '\r\n') || true
  if [ -n "$cc" ] && [ ${#cc} -le 3 ]; then printf "%s\n" "$cc"; return 0; fi
  cc=$(curl -fsS --max-time "$CURL_MAXTIME" "https://ipapi.co/$ip/country/" 2>/dev/null | tr -d '\r\n') || true
  if [ -n "$cc" ]; then printf "%s\n" "$cc"; return 0; fi
  return 1
}

geo_cc() {
  local ip="$1" cc=""
  if command -v mmdblookup >/dev/null 2>&1; then cc=$(geo_cc_mmdb "$ip" || true); fi
  if [ -z "$cc" ]; then cc=$(geo_cc_http "$ip" || true); fi
  printf "%s\n" "$cc"
}

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
  sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n1
}

ifconfig_v4() { curl -4 -fsS --max-time "$CURL_MAXTIME" https://ifconfig.co/json 2>/dev/null || true; }
ifconfig_v6() { curl -6 -fsS --max-time "$CURL_MAXTIME" https://ifconfig.co/json 2>/dev/null || true; }

main() {
  # Print title without parentheses to avoid any exotic parsing issues
  printf "%b" "$CYAN"
  printf "Consolidated Leak Test IPv4/IPv6\n"
  printf "%b" "$NC"
  hr 60
  printf "Expected router DNS: %s\n" "$ROUTER_DNS"
  if [ -n "$EXPECT_COUNTRY" ]; then printf "Expected egress country: %s\n" "$EXPECT_COUNTRY"; fi
  printf "\n"

  # [1] Resolver check
  printf "[1/6] DNS resolver used by this host (dig stats)\n"
  local used_resolver leak_dns=0
  used_resolver=$(resolver_used)
  printf "Resolver used: %s\n" "${used_resolver:-unknown}"
  if [ -n "$used_resolver" ] && [ -n "$ROUTER_DNS" ] && [ "$used_resolver" != "$ROUTER_DNS" ]; then
    printf "%bWARNING:%b Queries appear to bypass %s\n" "$RED" "$NC" "$ROUTER_DNS"
    leak_dns=1
  else
    printf "%bOK:%b Resolver matches expected (or unknown)\n" "$GREEN" "$NC"
  fi
  printf "\n"

  # [2] Router CHAOS TXT
  printf "[2/6] Router CHAOS TXT (dnsmasq hint)\n"
  chaos_val="$(dnsmasq_chaos)"
  printf "CHAOS @%s: %s\n" "$ROUTER_DNS" "$chaos_val"
  printf "\n"

  # [3] IPv4 egress via DNS-only + Geo
  printf "[3/6] IPv4 public IP via DNS-only and Geo\n"
  local v4_ip v4_cymru v4_cc_cymru v4_cc_nerd
  v4_ip=$(ipv4_public_dns)
  if printf "%s\n" "$v4_ip" | awk -F. 'NF==4{ok=1; for(i=1;i<=4;i++){ if($i!~/^[0-9]+$/||$i<0||$i>255){ok=0} } } END{exit ok?0:1}'; then
    printf "IPv4 (DNS): %s\n" "$v4_ip"
    v4_cymru=$(ipv4_cymru_line "$v4_ip")
    v4_cc_cymru=$(ipv4_cymru_cc "$v4_ip")
    v4_cc_nerd=$(ipv4_nerddk_cc "$v4_ip")
    v4_cc_geo=$(geo_cc "$v4_ip")
    printf "Team Cymru: %s\n" "${v4_cymru:-n/a}"
    printf "Country (Cymru): %s\n" "${v4_cc_cymru:-n/a}"
    printf "Country (nerd.dk): %s\n" "${v4_cc_nerd:-n/a}"
    if [ -n "${v4_cc_geo:-}" ]; then printf "Country (GeoIP): %s\n" "${v4_cc_geo}"; fi
  else
    printf "%bNOTE:%b Could not obtain IPv4 via DNS-only\n" "$YELLOW" "$NC"
  fi
  printf "\n"

  # [4] IPv4 via HTTPS API (ifconfig.co/json)
  printf "[4/6] IPv4 egress via ifconfig.co/json\n"
  local v4_json v4_api_ip v4_api_cc
  v4_json=$(ifconfig_v4)
  if [ -n "$v4_json" ]; then
    v4_api_ip=$(printf "%s" "$v4_json" | json_field ip)
    v4_api_cc=$(printf "%s" "$v4_json" | json_field country_iso)
    printf "IPv4 API IP: %s\n" "${v4_api_ip:-n/a}"
    printf "IPv4 API Country: %s\n" "${v4_api_cc:-n/a}"
  else
    printf "%bNOTE:%b IPv4 API request failed\n" "$YELLOW" "$NC"
  fi
  printf "\n"

  # [5] IPv6 egress via ifconfig.co/json (treat unavailable as OK)
  printf "[5/6] IPv6 egress (ifconfig.co/json over IPv6)\n"
  local v6_json v6_api_ip v6_api_cc v6_available=0
  v6_json=$(ifconfig_v6)
  if [ -n "$v6_json" ]; then
    v6_api_ip=$(printf "%s" "$v6_json" | json_field ip)
    v6_api_cc=$(printf "%s" "$v6_json" | json_field country_iso)
    if [ -n "$v6_api_ip" ]; then v6_available=1; fi
    printf "IPv6 API IP: %s\n" "${v6_api_ip:-n/a}"
    printf "IPv6 API Country: %s\n" "${v6_api_cc:-n/a}"
  else
    printf "IPv6 appears unavailable (no response over v6)  treated as OK\n"
  fi
  printf "\n"

  # [6] Resolver POP hints
  printf "[6/6] Resolver POP hints\n"
  cf_line="$(cf_pop)"
  odns_line="$(odns_dbg)"
  printf "Cloudflare id.server @1.1.1.1 | @1.0.0.1: %s\n" "$cf_line"
  printf "OpenDNS debug: %s\n" "$odns_line"
  printf "\n"

  # Summary
  hr 60
  printf "Summary:\n"
  printf "  Resolver used: %s (expected: %s)\n" "${used_resolver:-unknown}" "$ROUTER_DNS"
  if [ -n "${v4_ip:-}" ]; then printf "  IPv4 (DNS) IP: %s | CC: %s/%s | GeoIP: %s\n" "$v4_ip" "${v4_cc_cymru:-?}" "${v4_cc_nerd:-?}" "${v4_cc_geo:-?}"; fi
  if [ -n "${v4_api_ip:-}" ]; then printf "  IPv4 (API) IP: %s | CC: %s\n" "${v4_api_ip:-}" "${v4_api_cc:-?}"; fi
  if [ "$v6_available" -eq 1 ]; then
    printf "  IPv6 (API) IP: %s | CC: %s\n" "${v6_api_ip:-?}" "${v6_api_cc:-?}"
  else
    printf "  IPv6: unavailable/disabled (OK)\n"
  fi
  if [ -n "$EXPECT_COUNTRY" ]; then printf "  Expected country: %s\n" "$EXPECT_COUNTRY"; fi

  local exit_code=0
  # DNS leak if resolver bypasses router
  if [ "$leak_dns" -eq 1 ]; then exit_code=2; fi

  # Country mismatch checks (if EXPECT_COUNTRY provided)
  if [ -n "$EXPECT_COUNTRY" ]; then
    # Consider a mismatch only if both independent sources (Cymru & nerd.dk) disagree
    if [ -n "${v4_cc_cymru:-}" ] || [ -n "${v4_cc_nerd:-}" ]; then
      if [ "${v4_cc_cymru:-X}" != "$EXPECT_COUNTRY" ] && [ "${v4_cc_nerd:-X}" != "$EXPECT_COUNTRY" ]; then
        printf "%bNOTE:%b IPv4 egress country differs from expectation\n" "$YELLOW" "$NC"
      fi
    fi
    # IPv6: only enforce if IPv6 is actually available
    if [ "$v6_available" -eq 1 ] && [ -n "${v6_api_cc:-}" ] && [ "$v6_api_cc" != "$EXPECT_COUNTRY" ]; then
      printf "%bWARNING:%b IPv6 egress country differs from expectation  possible IPv6 leak\n" "$RED" "$NC"
      exit_code=2
    fi
  fi

  if [ "$exit_code" -eq 0 ]; then
    printf "%bNo leaks detected%b (resolver OK; IPv6 disabled or matches expectations)\n" "$GREEN" "$NC"
  else
    printf "%bPotential leak detected%b  see warnings above\n" "$RED" "$NC"
  fi
  exit "$exit_code"
}

main "$@"
