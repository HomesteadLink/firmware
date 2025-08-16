#!/bin/bash
#
# USB Router Setup Script
# Configures an Orange Pi (or similar SBC) as a USB ethernet router with VPN support
# Features: RNDIS/CDC ethernet gadget, DHCP server, NAT, OpenVPN, Tailscale
#
# Usage: sudo bash setup-usb-router.sh
#

set -e

# Configuration variables
USB_NETWORK="192.168.64.0/24"
USB_IP="192.168.64.1"
USB_DHCP_START="192.168.64.50"
USB_DHCP_END="192.168.64.150"
USB_INTERFACE="usb0"
WAN_INTERFACE="${WAN_INTERFACE:-wlan0}"  # Can be overridden by environment variable
TAILSCALE_INTERFACE="tailscale0"
OPENVPN_INTERFACE="tun0"
USE_TAILSCALE_EXIT="${USE_TAILSCALE_EXIT:-true}"  # Default: route through VPN only
USE_VPN_FAILOVER="${USE_VPN_FAILOVER:-true}"  # Enable automatic VPN failover

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect the distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        CODENAME=${VERSION_CODENAME:-}
    else
        log_error "Cannot detect OS distribution"
        exit 1
    fi
    if [ -n "$CODENAME" ]; then
        log_info "Detected OS: $OS $VER ($CODENAME)"
    else
        log_info "Detected OS: $OS $VER"
    fi
}

# Board plugin loader (sources boards/*/setup.sh and selects matching board)
BOARD_NAME=""
BOARD_OVERRIDES_GADGET=false

load_board_plugin() {
    local script_dir boards_dir f
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    boards_dir="$script_dir/boards"
    for f in "$boards_dir"/*/setup.sh; do
        [ -f "$f" ] || continue
        # shellcheck source=/dev/null
        . "$f"
        if declare -F board_detect >/dev/null && board_detect; then
            : "${BOARD_NAME:=$(basename "$(dirname "$f")")}"
            log_info "Board detected: $BOARD_NAME (plugin: $(basename "$(dirname "$f")"))"
            return 0
        fi
        # No match; cleanup symbols before trying next
        unset -f board_detect 2>/dev/null || true
        unset -f board_required_packages 2>/dev/null || true
        unset -f board_apply_dts_overlay 2>/dev/null || true
        unset -f board_setup_gadget 2>/dev/null || true
        unset BOARD_NAME BOARD_OVERRIDES_GADGET 2>/dev/null || true
    done
    return 0
}

# Install required packages
install_packages() {
    log_info "Checking and installing required packages..."
    
    case $OS in
        debian|ubuntu|armbian)
            # List of required packages
            local packages=(
                dnsmasq
                netfilter-persistent
                nftables
                tcpdump
                curl
                gnupg
                lsb-release
                ca-certificates
                openvpn
                jq
            )
            # Merge board-specific packages if plugin defines them
            if declare -F board_required_packages >/dev/null; then
                local board_pkgs
                # shellcheck disable=SC2207
                board_pkgs=($(board_required_packages))
                if [ ${#board_pkgs[@]} -gt 0 ]; then
                    for pkg in "${board_pkgs[@]}"; do
                        packages+=("$pkg")
                    done
                fi
            fi
            
            # Check which packages need to be installed
            local to_install=()
            for pkg in "${packages[@]}"; do
                if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
                    to_install+=("$pkg")
                fi
            done
            
            # Only run apt if there are packages to install
            if [ ${#to_install[@]} -gt 0 ]; then
                log_info "Need to install: ${to_install[*]}"
                apt-get update
                apt-get install -y "${to_install[@]}"
            else
                log_info "All required packages are already installed"
            fi
            ;;
        *)
            log_error "Unsupported distribution: $OS"
            exit 1
            ;;
    esac
}

# Configure USB gadget modules
setup_usb_gadget() {
    log_info "Configuring USB gadget modules..."
    # If a board plugin wants to fully handle gadget setup, delegate and return
    if [ "${BOARD_OVERRIDES_GADGET:-false}" = "true" ] && declare -F board_setup_gadget >/dev/null; then
        log_info "Delegating USB gadget setup to board plugin: ${BOARD_NAME:-unknown}"
        board_setup_gadget
        return
    fi
    
    # Standard configuration for generic boards
    cat > /etc/modules-load.d/usb_gadget.conf << EOF
# USB Ethernet Gadget
g_ether
EOF
    
    # Create modprobe configuration for g_ether
    cat > /etc/modprobe.d/g_ether.conf << EOF
# Use CDC-ECM mode for better macOS compatibility
options g_ether use_eem=0 use_ecm=1
EOF

    # Load the module now if not already loaded
    if ! lsmod | grep -q g_ether; then
        # Load without parameters so it uses /etc/modprobe.d/g_ether.conf
        modprobe g_ether
        sleep 2
    else
        log_info "g_ether already loaded - may need reboot for new options to take effect"
    fi
}

# Configure network interface
setup_network_interface() {
    log_info "Configuring network interface for $USB_INTERFACE..."
    
    # Check if using systemd-networkd (preferred on modern systems)
    if systemctl is-enabled systemd-networkd &>/dev/null || [ -d /etc/systemd/network ]; then
        log_info "Configuring via systemd-networkd..."
        # Remove any old configs with wrong IP
        rm -f /etc/systemd/network/*usb0*.network 2>/dev/null
        
        cat > /etc/systemd/network/20-usb0.network << EOF
[Match]
Name=$USB_INTERFACE

[Network]
Address=$USB_IP/24
ConfigureWithoutCarrier=yes

[Link]
RequiredForOnline=no
EOF
        systemctl enable systemd-networkd 2>/dev/null || true
        systemctl restart systemd-networkd || true
    elif [ -d /etc/netplan ]; then
        # Netplan configuration
        cat > /etc/netplan/40-usb0.yaml << EOF
network:
  version: 2
  ethernets:
    $USB_INTERFACE:
      addresses:
        - $USB_IP/24
      optional: true
EOF
        chmod 600 /etc/netplan/40-usb0.yaml
        netplan apply || true
    else
        # Traditional /etc/network/interfaces
        if ! grep -q "$USB_INTERFACE" /etc/network/interfaces; then
            cat >> /etc/network/interfaces << EOF

# USB Ethernet Gadget Interface
auto $USB_INTERFACE
iface $USB_INTERFACE inet static
    address $USB_IP
    netmask 255.255.255.0
EOF
        fi
    fi
}

# Configure DHCP server
setup_dhcp_server() {
    log_info "Configuring DHCP server..."
    
    # Stop and disable systemd-resolved to avoid port 53 conflicts
    if systemctl is-active systemd-resolved &>/dev/null; then
        log_info "Disabling systemd-resolved to avoid conflicts..."
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
    fi
    
    # Backup original dnsmasq config if exists
    [ -f /etc/dnsmasq.conf ] && cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
    
    # Clear any existing dnsmasq.d configs that might conflict
    rm -f /etc/dnsmasq.d/*.conf 2>/dev/null
    
    # Create main dnsmasq configuration
    cat > /etc/dnsmasq.conf << EOF
# DHCP Configuration for USB Ethernet Gadget
interface=$USB_INTERFACE
bind-interfaces
except-interface=lo
dhcp-range=$USB_DHCP_START,$USB_DHCP_END,12h
dhcp-option=3,$USB_IP
dhcp-option=6,$USB_IP

# DNS Configuration
port=53
server=8.8.8.8
server=1.1.1.1
cache-size=150
domain-needed
bogus-priv

# Logging
log-dhcp
log-queries
log-facility=/var/log/dnsmasq.log
EOF

    # Create systemd override to ensure dnsmasq starts after usb0
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    cat > /etc/systemd/system/dnsmasq.service.d/wait-for-usb0.conf << EOF
[Unit]
After=sys-subsystem-net-devices-$USB_INTERFACE.device
Wants=sys-subsystem-net-devices-$USB_INTERFACE.device

[Service]
# Restart if it fails (in case usb0 isn't ready yet)
Restart=on-failure
RestartSec=5s
EOF

    systemctl daemon-reload
    systemctl enable dnsmasq
}

# Configure IP forwarding and NAT
setup_nat() {
    log_info "Configuring IP forwarding and NAT..."
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/30-ip-forward.conf
    sysctl -w net.ipv4.ip_forward=1
    
    # Use nftables: create dedicated tables that lock down forwarding and apply masquerade
    # Clean up previous runs
    if command -v nft &>/dev/null; then
        nft list table inet usb_router_filter &>/dev/null && nft delete table inet usb_router_filter || true
        nft list table ip usb_router_nat &>/dev/null && nft delete table ip usb_router_nat || true
        
        # Build ruleset: only allow usb0 -> tailscale0/tun0 and established back; drop everything else on forward
        nft -f - <<EOF
table inet usb_router_filter {
  chain forward {
    type filter hook forward priority 0;
    policy drop;
    ct state established,related accept
    iifname "${USB_INTERFACE}" oifname "${TAILSCALE_INTERFACE}" accept
    iifname "${USB_INTERFACE}" oifname "${OPENVPN_INTERFACE}" accept
    oifname "${USB_INTERFACE}" ct state related,established accept
  }
}

table ip usb_router_nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr ${USB_NETWORK} oifname "${TAILSCALE_INTERFACE}" masquerade
    ip saddr ${USB_NETWORK} oifname "${OPENVPN_INTERFACE}" masquerade
  }
}
EOF
        log_info "Applied nftables rules: forward only usb0->tailscale0/tun0 with masquerade"
    else
        log_warn "nft command not found; cannot apply nftables rules"
    fi
    
    if [ "$USE_TAILSCALE_EXIT" = "true" ]; then
        log_info "Setting up VPN-only routing for USB clients"
        
        # Create custom routing table for USB clients
        if ! grep -q "usb_vpn" /etc/iproute2/rt_tables; then
            echo "200 usb_vpn" >> /etc/iproute2/rt_tables
        fi
        
        # Only route USB client traffic through VPN, not the device's own traffic
        ip rule del from $USB_NETWORK table usb_vpn 2>/dev/null || true
        ip rule add from $USB_NETWORK table usb_vpn priority 200
        
        # Wait for Tailscale interface
        local attempts=0
        while [ $attempts -lt 10 ] && ! ip link show $TAILSCALE_INTERFACE &>/dev/null; do
            log_info "Waiting for Tailscale interface..."
            sleep 2
            ((attempts++))
        done
        
        # Add default route through Tailscale for USB clients only
        if ip link show $TAILSCALE_INTERFACE &>/dev/null; then
            local ts_gateway=$(ip route show dev $TAILSCALE_INTERFACE | grep -E '^100\.' | head -1 | awk '{print $1}')
            if [ -n "$ts_gateway" ]; then
                ip route add default via $ts_gateway dev $TAILSCALE_INTERFACE table usb_vpn 2>/dev/null || true
            fi
        fi
        
        # Forwarding and masquerade already handled by nftables above
        log_info "USB clients can ONLY route through VPN interfaces (nftables enforced)"
        
        # Ensure local traffic is not affected
        ip rule add from 192.168.0.0/16 to 192.168.0.0/16 table main priority 50
        ip rule add from 10.0.0.0/8 to 10.0.0.0/8 table main priority 50
        
        log_info "No leaks possible: forwarding restricted to ${TAILSCALE_INTERFACE} and ${OPENVPN_INTERFACE}"
    else
        # Even when not using Tailscale exit, keep forwarding restricted to VPN interfaces only
        log_info "Restricting forwarding to VPN interfaces only via nftables"
    fi
    
    # Persist firewall rules using netfilter-persistent and nftables
    mkdir -p /etc/iptables
    if command -v netfilter-persistent &>/dev/null; then
        log_info "Saving firewall rules via netfilter-persistent"
        netfilter-persistent save || true
    fi

    # Detect if we are running inside a chroot
    in_chroot=false
    if command -v systemd-detect-virt &>/dev/null && systemd-detect-virt --chroot --quiet; then
        in_chroot=true
    fi

    if command -v nft &>/dev/null; then
        if [ "$in_chroot" = true ]; then
            # In chroot: don't query host kernel ruleset; write our intended config directly
            log_info "Chroot detected: writing nftables config to /etc/nftables.conf without querying kernel"
            cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f
flush ruleset

table inet usb_router_filter {
  chain forward {
    type filter hook forward priority 0;
    policy drop;
    ct state established,related accept
    iifname "${USB_INTERFACE}" oifname "${TAILSCALE_INTERFACE}" accept
    iifname "${USB_INTERFACE}" oifname "${OPENVPN_INTERFACE}" accept
    oifname "${USB_INTERFACE}" ct state related,established accept
  }
}

table ip usb_router_nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr ${USB_NETWORK} oifname "${TAILSCALE_INTERFACE}" masquerade
    ip saddr ${USB_NETWORK} oifname "${OPENVPN_INTERFACE}" masquerade
  }
}
EOF
            # Skip systemctl in chroot
        else
            # On a real system, persist the live ruleset and enable service
            log_info "Writing current nftables ruleset to /etc/nftables.conf and enabling nftables service"
            nft list ruleset > /etc/nftables.conf 2>/dev/null || true
            systemctl enable nftables 2>/dev/null || true
            systemctl restart nftables 2>/dev/null || true
        fi
    fi

    # Fallback: also save iptables rules to rules.v4 for compatibility (may be empty when using nftables)
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
}

# Install and configure OpenVPN
setup_openvpn() {
    log_info "Setting up OpenVPN client..."
    
    # Create OpenVPN client config directory
    mkdir -p /etc/openvpn/client
    
    # Create a template systemd service for OpenVPN clients
    cat > /etc/systemd/system/openvpn-client@.service << EOF
[Unit]
Description=OpenVPN client for %i
After=network.target

[Service]
Type=notify
PrivateTmp=true
ExecStart=/usr/sbin/openvpn --config /etc/openvpn/client/%i.ovpn
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    log_info "OpenVPN client installed. Place your .ovpn files in /etc/openvpn/client/"
    log_info "Start with: systemctl start openvpn-client@configname"
}

# Install and configure Tailscale
setup_tailscale() {
    log_info "Installing Tailscale..."
    
    # Add Tailscale's GPG key and repository
    if command -v tailscale >/dev/null 2>&1; then
        log_info "Tailscale already installed"
    else
        case $OS in
        debian|ubuntu|armbian)
            # Install dependencies including jq for JSON parsing
            apt-get install -y jq
            
            curl -fsSL https://pkgs.tailscale.com/stable/debian/bullseye.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
            curl -fsSL https://pkgs.tailscale.com/stable/debian/bullseye.tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list
            
                apt-get update
            apt-get install -y tailscale
                ;;
        esac
    fi
    
    systemctl enable tailscaled
    systemctl start tailscaled
    
    # Configure Tailscale to accept subnet routes and act as exit node
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-tailscale.conf << EOF
# Enable IP forwarding for Tailscale
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -p /etc/sysctl.d/99-forwarding.conf
    
    # If USE_TAILSCALE_EXIT is true, we'll use split routing (USB clients only)
    if [ "$USE_TAILSCALE_EXIT" = "true" ]; then
        log_info "Checking Tailscale authentication status..."
        if tailscale status &>/dev/null; then
            log_info "Tailscale is authenticated"
            log_info "Split routing will be configured - USB clients through VPN, device keeps local access"
            
            # Make sure we allow local network access
            tailscale set --exit-node-allow-lan-access=true 2>/dev/null || true
        else
            log_warn "Tailscale not authenticated yet. Run 'tailscale up' first"
        fi
    fi
    
    log_info "Tailscale installed. Commands:"
    log_info "  tailscale up                    - Authenticate with Tailscale"
    log_info "  usb-router-tailscale on         - Route USB clients through Tailscale"
    log_info "  usb-router-tailscale off        - Route USB clients through local internet"
    log_info "  tailscale up --advertise-exit-node  - Make this device an exit node"
}

# Create helper scripts
create_helper_scripts() {
    log_info "Creating helper scripts..."
    
    # Status check script
    cat > /usr/local/bin/usb-router-status << 'EOF'
#!/bin/bash
echo "=== USB Router Status ==="
echo
echo "USB Interface:"
ip addr show usb0 2>/dev/null || echo "  Interface not found"
echo
echo "DHCP Leases:"
if [ -f /var/lib/misc/dnsmasq.leases ]; then
    cat /var/lib/misc/dnsmasq.leases | awk '{print "  "$3" - "$4}'
else
    echo "  No active leases"
fi
echo
echo "NAT Rules:"
iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE
echo
echo "Routing:"
if ip rule show | grep -q "from $USB_NETWORK table usb_vpn"; then
    echo "  USB clients use VPN routing table"
    current_route=$(ip route show table usb_vpn 2>/dev/null | grep default || echo "No default route")
    if echo "$current_route" | grep -q "tailscale0"; then
        echo "  Active VPN: Tailscale"
    elif echo "$current_route" | grep -q "tun0"; then
        echo "  Active VPN: OpenVPN (failover)"
    else
        echo "  Active VPN: None configured"
    fi
else
    echo "  Traffic routed through: Local WAN"
fi
echo ""
echo "VPN Status:"
echo "  Tailscale: $(ip link show tailscale0 &>/dev/null && echo "UP" || echo "DOWN")"
echo "  OpenVPN: $(ip link show tun0 &>/dev/null && echo "UP" || echo "DOWN")"
if systemctl is-active usb-router-vpn-monitor &>/dev/null; then
    echo "  Failover Monitor: Active"
else
    echo "  Failover Monitor: Inactive"
fi
echo
echo "Services:"
systemctl is-active dnsmasq | xargs echo "  dnsmasq:"
systemctl is-active tailscaled | xargs echo "  tailscale:"
EOF
    chmod +x /usr/local/bin/usb-router-status
    
    # Tailscale routing switch script
    cat > /usr/local/bin/usb-router-tailscale << 'EOF'
#!/bin/bash
set -e

usage() {
  echo "Usage: $0 {on|off|status}"
  echo "  on     - Enable and select a Tailscale exit node"
  echo "  off    - Disable exit node (no routing changes in iptables)"
  echo "  status - Show Tailscale status and current exit node"
  exit 1
}

require_ts() {
  command -v tailscale >/dev/null 2>&1 || { echo "tailscale CLI not found"; exit 1; }
  tailscale status >/dev/null 2>&1 || { echo "Tailscale not authenticated. Run: tailscale up"; exit 1; }
}

get_exit_nodes() {
  tailscale status --json | jq -r '.Peer[] | select(.ExitNodeOption==true) | .HostName' 2>/dev/null || true
}

select_exit_node() {
  local nodes=($(get_exit_nodes))
  if [ ${#nodes[@]} -eq 0 ]; then
    echo ""; return 1
  elif [ ${#nodes[@]} -eq 1 ]; then
    echo "${nodes[0]}"; return 0
  else
    echo "Available exit nodes:"
    local i=1
    for n in "${nodes[@]}"; do echo "  $i) $n"; ((i++)); done
    read -p "Select exit node (1-${#nodes[@]}): " sel
    if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#nodes[@]} ]; then
      echo "${nodes[$((sel-1))]}"; return 0
    fi
    return 1
  fi
}

cmd_on() {
  require_ts
  tailscale set --exit-node-allow-lan-access=true 2>/dev/null || true
  node="$(select_exit_node)" || { echo "No exit nodes available. Ensure one is advertised and shared."; exit 1; }
  echo "Enabling exit node: $node"
  tailscale set --exit-node="$node"
}

cmd_off() {
  require_ts
  echo "Clearing exit node"
  tailscale set --exit-node=
}

cmd_status() {
  require_ts
  echo "Tailscale status:"
  tailscale status | sed 's/^/  /'
  cur=$(tailscale status --json | jq -r '.Self.ExitNode | select(.!=null)')
  if [ -n "$cur" ]; then
    echo "Current exit node: $cur"
  else
    echo "Current exit node: none"
  fi
}

case "${1:-status}" in
  on) cmd_on ;;
  off) cmd_off ;;
  status) cmd_status ;;
  *) usage ;;
esac
EOF
    chmod +x /usr/local/bin/usb-router-tailscale
    
    # VPN failover monitoring script
    cat > /usr/local/bin/usb-router-vpn-monitor << 'EOF'
#!/bin/bash
# Monitor VPN connections and implement failover

LOG_FILE="/var/log/usb-router-vpn-monitor.log"
CHECK_INTERVAL=30  # seconds
PING_TIMEOUT=5     # seconds
TEST_HOST="1.1.1.1"  # Cloudflare DNS for connectivity test
USB_NETWORK="192.168.64.0/24"
TAILSCALE_INTERFACE="tailscale0"
OPENVPN_INTERFACE="tun0"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

check_interface() {
    local interface=$1
    ip link show "$interface" &>/dev/null && \
    ip addr show "$interface" | grep -q "inet "
}

check_connectivity() {
    local interface=$1
    ping -I "$interface" -c 1 -W "$PING_TIMEOUT" "$TEST_HOST" &>/dev/null
}

get_current_vpn() {
    # Check which VPN is currently routing USB traffic
    if ip route show table usb_vpn 2>/dev/null | grep -q "$TAILSCALE_INTERFACE"; then
        echo "tailscale"
    elif ip route show table usb_vpn 2>/dev/null | grep -q "$OPENVPN_INTERFACE"; then
        echo "openvpn"
    else
        echo "none"
    fi
}

switch_to_tailscale() {
    log_msg "Switching USB routing to Tailscale..."
    
    # Update routing table
    ip route del default table usb_vpn 2>/dev/null || true
    local ts_gateway=$(ip route show dev $TAILSCALE_INTERFACE | grep -E '^100\.' | head -1 | awk '{print $1}')
    if [ -n "$ts_gateway" ]; then
        ip route add default via $ts_gateway dev $TAILSCALE_INTERFACE table usb_vpn
    else
        ip route add default dev $TAILSCALE_INTERFACE table usb_vpn
    fi
    
    # Update iptables
    iptables -t nat -D POSTROUTING -o $OPENVPN_INTERFACE -s $USB_NETWORK -j MASQUERADE 2>/dev/null || true
    iptables -t nat -C POSTROUTING -o $TAILSCALE_INTERFACE -s $USB_NETWORK -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o $TAILSCALE_INTERFACE -s $USB_NETWORK -j MASQUERADE
    
    log_msg "Switched to Tailscale successfully"
}

switch_to_openvpn() {
    log_msg "Switching USB routing to OpenVPN..."
    
    # Update routing table
    ip route del default table usb_vpn 2>/dev/null || true
    # OpenVPN usually sets up routes automatically, just use the interface
    ip route add default dev $OPENVPN_INTERFACE table usb_vpn
    
    # Update iptables
    iptables -t nat -D POSTROUTING -o $TAILSCALE_INTERFACE -s $USB_NETWORK -j MASQUERADE 2>/dev/null || true
    iptables -t nat -C POSTROUTING -o $OPENVPN_INTERFACE -s $USB_NETWORK -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o $OPENVPN_INTERFACE -s $USB_NETWORK -j MASQUERADE
    
    log_msg "Switched to OpenVPN successfully"
}

monitor_loop() {
    log_msg "VPN failover monitor started"
    
    while true; do
        current_vpn=$(get_current_vpn)
        tailscale_up=false
        openvpn_up=false
        
        # Check Tailscale
        if check_interface "$TAILSCALE_INTERFACE" && check_connectivity "$TAILSCALE_INTERFACE"; then
            tailscale_up=true
        fi
        
        # Check OpenVPN
        if check_interface "$OPENVPN_INTERFACE" && check_connectivity "$OPENVPN_INTERFACE"; then
            openvpn_up=true
        fi
        
        # Implement failover logic
        case "$current_vpn" in
            "tailscale")
                if ! $tailscale_up && $openvpn_up; then
                    log_msg "Tailscale down, failing over to OpenVPN"
                    switch_to_openvpn
                fi
                ;;
            "openvpn")
                if $tailscale_up; then
                    log_msg "Tailscale is back up, switching back from OpenVPN"
                    switch_to_tailscale
                elif ! $openvpn_up; then
                    log_msg "WARNING: OpenVPN is down and Tailscale unavailable!"
                fi
                ;;
            "none")
                if $tailscale_up; then
                    log_msg "Tailscale available, enabling VPN routing"
                    switch_to_tailscale
                elif $openvpn_up; then
                    log_msg "OpenVPN available, enabling VPN routing"
                    switch_to_openvpn
                else
                    log_msg "WARNING: No VPN connections available!"
                fi
                ;;
        esac
        
        sleep "$CHECK_INTERVAL"
    done
}

# Command line interface
case "${1:-monitor}" in
    "status")
        echo "Current VPN: $(get_current_vpn)"
        echo "Tailscale: $(check_interface $TAILSCALE_INTERFACE && echo "UP" || echo "DOWN")"
        echo "OpenVPN: $(check_interface $OPENVPN_INTERFACE && echo "UP" || echo "DOWN")"
        ;;
    "monitor")
        monitor_loop
        ;;
    *)
        echo "Usage: $0 {monitor|status}"
        exit 1
        ;;
esac
EOF
    chmod +x /usr/local/bin/usb-router-vpn-monitor
    
    # Create systemd service for VPN monitor
    cat > /etc/systemd/system/usb-router-vpn-monitor.service << EOF
[Unit]
Description=USB Router VPN Failover Monitor
After=network.target tailscaled.service
Wants=tailscaled.service

[Service]
Type=simple
ExecStart=/usr/local/bin/usb-router-vpn-monitor monitor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Create USB interface watchdog to handle macOS permission delays
    cat > /usr/local/bin/usb-interface-watchdog << 'EOF'
#!/bin/bash
# Watchdog to handle USB interface appearing after macOS permission approval

LOG_FILE="/var/log/usb-interface-watchdog.log"
USB_INTERFACE="usb0"
CHECK_INTERVAL=10
MAX_WAIT=300  # 5 minutes max wait

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

wait_for_interface() {
    local waited=0
    
    while [ $waited -lt $MAX_WAIT ]; do
        if ip link show $USB_INTERFACE &>/dev/null; then
            log_msg "USB interface $USB_INTERFACE detected!"
            
            # Configure the interface
            ip link set $USB_INTERFACE up
            ip addr add 192.168.64.1/24 dev $USB_INTERFACE 2>/dev/null || true
            
            # Restart dnsmasq if it's not running
            if ! systemctl is-active dnsmasq &>/dev/null; then
                log_msg "Starting dnsmasq..."
                systemctl restart dnsmasq
            elif ! systemctl status dnsmasq | grep -q "usb0"; then
                log_msg "Restarting dnsmasq to bind to USB interface..."
                systemctl restart dnsmasq
            fi
            
            return 0
        fi
        
        sleep $CHECK_INTERVAL
        waited=$((waited + CHECK_INTERVAL))
    done
    
    log_msg "Timeout waiting for USB interface"
    return 1
}

monitor_interface() {
    log_msg "USB interface watchdog started"
    
    while true; do
        if ! ip link show $USB_INTERFACE &>/dev/null; then
            log_msg "USB interface not found, waiting for macOS permission..."
            wait_for_interface
        else
            # Check if dnsmasq is healthy
            if ! systemctl is-active dnsmasq &>/dev/null; then
                log_msg "dnsmasq is not running, restarting..."
                systemctl restart dnsmasq
            fi
        fi
        
        sleep $CHECK_INTERVAL
    done
}

case "${1:-monitor}" in
    "monitor")
        monitor_interface
        ;;
    "check")
        if ip link show $USB_INTERFACE &>/dev/null; then
            echo "USB interface: UP"
            systemctl is-active dnsmasq && echo "dnsmasq: ACTIVE" || echo "dnsmasq: INACTIVE"
        else
            echo "USB interface: DOWN (waiting for macOS permission?)"
        fi
        ;;
    *)
        echo "Usage: $0 {monitor|check}"
        exit 1
        ;;
esac
EOF
    chmod +x /usr/local/bin/usb-interface-watchdog
    
    # Create systemd service for USB watchdog
    cat > /etc/systemd/system/usb-interface-watchdog.service << EOF
[Unit]
Description=USB Interface Watchdog for macOS Permission Delays
After=network.target
Before=dnsmasq.service

[Service]
Type=simple
ExecStart=/usr/local/bin/usb-interface-watchdog monitor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable usb-interface-watchdog.service
    log_info "USB interface watchdog enabled (handles macOS permission delays)"
    
    if [ "$USE_VPN_FAILOVER" = "true" ]; then
        systemctl enable usb-router-vpn-monitor.service
        log_info "VPN failover monitoring enabled"
    fi
}

# Main setup function
main() {
    log_info "Starting USB Router Setup..."
    
    check_root
    detect_distro
    load_board_plugin
    install_packages
    if declare -F board_apply_dts_overlay >/dev/null; then
        log_info "Applying board DTS overlay via plugin"
        board_apply_dts_overlay
    fi
    setup_usb_gadget
    setup_network_interface
    setup_dhcp_server
    setup_nat
    setup_openvpn
    setup_tailscale
    create_helper_scripts
    
    # Restart services
    log_info "Restarting services..."
    systemctl restart systemd-networkd || true
    
    # Try to bring up usb0 if module is loaded
    if lsmod | grep -q g_ether; then
        sleep 2
        ip link set $USB_INTERFACE up 2>/dev/null || true
        systemctl restart dnsmasq || true
    fi
    
    # Check if reboot is required (for RK3399 boards)
    if [ "${REBOOT_REQUIRED:-false}" = "true" ]; then
        log_warn "IMPORTANT: REBOOT REQUIRED!"
        log_warn "The USB device tree overlay has been applied."
        log_warn "You must reboot for USB peripheral mode to work."
        log_warn ""
        log_warn "For Orange Pi 4 LTS: Due to a FUSB302 initialization bug,"
        log_warn "connect power AND USB-C cable simultaneously during boot"
        log_warn "for best results. This ensures peripheral mode is properly set."
        log_info ""
        read -p "Reboot now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            reboot
        fi
    else
        # Check if UDC is available (for boards that don't need reboot)
        if ls /sys/class/udc/ 2>/dev/null | grep -q .; then
            log_info "USB Device Controller found: $(ls /sys/class/udc/)"
            log_info "USB gadget should be working!"
        else
            log_warn "No USB Device Controller found. You may need to reboot."
        fi
    fi
    
    log_info "Setup complete!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Connect USB cable to host computer"
    log_info "2. Host should receive IP via DHCP in range $USB_DHCP_START-$USB_DHCP_END"
    log_info "3. Configure OpenVPN: place .ovpn files in /etc/openvpn/client/"
    log_info "4. Configure Tailscale: run 'tailscale up'"
    log_info ""
    log_info "Helper commands:"
    log_info "  usb-router-status          - Check router status"
    log_info "  usb-router-reset           - Reset USB interface"
    log_info "  usb-router-tailscale       - Switch between local/Tailscale routing"
    log_info "  usb-router-vpn-monitor     - Check VPN failover status"
    log_info "  usb-interface-watchdog     - Check USB interface watchdog"
    log_info ""
    log_info "VPN Failover:"
    log_info "  - Tailscale is primary VPN (when available)"
    log_info "  - OpenVPN automatically takes over if Tailscale fails"
    log_info "  - Monitor service: systemctl status usb-router-vpn-monitor"
    log_info ""
    log_info "To configure OpenVPN backup:"
    log_info "  1. Place .ovpn file in /etc/openvpn/client/"
    log_info "  2. Start: systemctl start openvpn-client@configname"
}

# Run main function
main "$@"