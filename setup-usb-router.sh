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

# Ensure system DNS resolver works (keep systemd-resolved enabled and resolv.conf present)
setup_system_dns() {
    if systemctl list-unit-files | grep -q '^systemd-resolved\.service'; then
        systemctl enable systemd-resolved 2>/dev/null || true
        # Prefer stub resolver; fall back to full if unavailable
        if [ -f /run/systemd/resolve/stub-resolv.conf ]; then
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
        elif [ -f /run/systemd/resolve/resolv.conf ]; then
            ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
        fi
    fi
}

# Ensure network time sync is enabled and perform an initial sync
setup_time_sync() {
    log_info "Configuring network time synchronization"
    if systemctl list-unit-files | grep -q '^systemd-timesyncd\.service'; then
        systemctl enable systemd-timesyncd 2>/dev/null || true
        systemctl start systemd-timesyncd 2>/dev/null || true
        # Enable NTP via timedatectl (idempotent)
        timedatectl set-ntp true 2>/dev/null || true
        # Give it a brief moment to sync if just enabled
        sleep 1
    else
        log_warn "systemd-timesyncd not available; consider installing chrony or ntp"
    fi
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
                systemd-timesyncd
                systemd-resolved
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
    
    # Composite gadget via configfs: ACM (serial) + ECM (ethernet)
    log_info "Setting up composite USB gadget (ACM + ECM) via configfs"
    local GADGET_SH="/usr/local/sbin/setup-usb-gadget.sh"
    mkdir -p /usr/local/sbin
    cat >"$GADGET_SH" <<'EOSH'
#!/bin/sh
set -e
modprobe libcomposite 2>/dev/null || true
# Mount configfs if not already
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
G=/sys/kernel/config/usb_gadget/pi
[ -d "$G" ] || mkdir -p "$G"
cd "$G"
# Linux Foundation IDs (gadget)
echo 0x1d6b > idVendor
echo 0x0104 > idProduct
mkdir -p strings/0x409
echo "USBVPN"       > strings/0x409/manufacturer
echo "USB VPN Router" > strings/0x409/product
echo "0001"          > strings/0x409/serialnumber
mkdir -p configs/c.1/strings/0x409
echo "ACM+ECM+RNDIS" > configs/c.1/strings/0x409/configuration
# Functions
mkdir -p functions/acm.usb0
mkdir -p functions/ecm.usb0
mkdir -p functions/rndis.usb0
# Optional MACs can be provided via environment
[ -n "$DEV_MAC" ]  && echo "$DEV_MAC"  > functions/ecm.usb0/dev_addr || true
[ -n "$HOST_MAC" ] && echo "$HOST_MAC" > functions/ecm.usb0/host_addr || true
[ -n "$DEV_MAC" ]  && echo "$DEV_MAC"  > functions/rndis.usb0/dev_addr || true
[ -n "$HOST_MAC" ] && echo "$HOST_MAC" > functions/rndis.usb0/host_addr || true
ln -sf functions/acm.usb0 configs/c.1/
ln -sf functions/ecm.usb0 configs/c.1/
ln -sf functions/rndis.usb0 configs/c.1/
# Enable Microsoft OS descriptors for better Windows support
mkdir -p os_desc
echo 1 > os_desc/use
echo MSFT100 > os_desc/qw_sign
echo 0x01 > os_desc/b_vendor_code
ln -sf configs/c.1 os_desc
# Bind to first available UDC
UDC=$(ls /sys/class/udc 2>/dev/null | head -n1 || true)
[ -n "$UDC" ] && echo "$UDC" > UDC || true
EOSH
    chmod +x "$GADGET_SH"

    # systemd unit to run gadget setup early
    mkdir -p /etc/systemd/system
    cat >/etc/systemd/system/usb-gadget.service <<'EOF'
[Unit]
Description=USB Gadget (ACM + ECM) bringup
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/setup-usb-gadget.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    ln -sf ../usb-gadget.service /etc/systemd/system/multi-user.target.wants/usb-gadget.service

    # Enable login on USB serial (ttyGS0) when available
    local GETTY_TEMPLATE=""
    for p in /lib/systemd/system/serial-getty@.service /usr/lib/systemd/system/serial-getty@.service; do
        [ -f "$p" ] && GETTY_TEMPLATE="$p" && break
    done
    if [ -n "$GETTY_TEMPLATE" ]; then
        mkdir -p /etc/systemd/system/getty.target.wants
        ln -sf "$GETTY_TEMPLATE" /etc/systemd/system/getty.target.wants/serial-getty@ttyGS0.service
    fi
}

# Configure network interface
setup_network_interface() {
    log_info "Configuring network interface for $USB_INTERFACE..."
    
    # If NetworkManager is active (common on Armbian), create a profile via nmcli
    if systemctl is-active NetworkManager &>/dev/null; then
        log_info "Configuring via NetworkManager..."
        if ! nmcli -t -f NAME con show | grep -Fxq "USB Gadget"; then
            nmcli con add type ethernet ifname "$USB_INTERFACE" con-name "USB Gadget" ipv4.method manual ipv4.addresses "$USB_IP/24" ipv6.method ignore autoconnect yes || true
        else
            nmcli con mod "USB Gadget" ipv4.method manual ipv4.addresses "$USB_IP/24" ipv6.method ignore autoconnect yes || true
        fi
        nmcli con up "USB Gadget" || true

    # Otherwise, check if using systemd-networkd (preferred on modern systems)
    elif systemctl is-enabled systemd-networkd &>/dev/null || [ -d /etc/systemd/network ]; then
        log_info "Configuring via systemd-networkd..."
        # Remove any old configs with wrong IP
        rm -f /etc/systemd/network/*usb0*.network 2>/dev/null
        
        cat > /etc/systemd/network/20-usb0.network << EOF
[Match]
Name=usb*

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
    
    # Keep systemd-resolved enabled for the host's own DNS.
    # dnsmasq will bind only to $USB_INTERFACE so there is no port 53 conflict.
    # (see interface= and bind-interfaces below)
    
    # Backup original dnsmasq config if exists
    [ -f /etc/dnsmasq.conf ] && cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
    
    # Clear any existing dnsmasq.d configs that might conflict
    rm -f /etc/dnsmasq.d/*.conf 2>/dev/null
    
    # Create main dnsmasq configuration
    cat > /etc/dnsmasq.conf << EOF
# DHCP Configuration for USB Ethernet Gadget
interface=usb*
bind-interfaces
except-interface=lo
dhcp-range=$USB_DHCP_START,$USB_DHCP_END,12h
dhcp-option=3,$USB_IP
dhcp-option=6,$USB_IP

# DNS Configuration
port=53
listen-address=$USB_IP
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
    
    # Enable IP forwarding (IPv4 and IPv6) in one place
    cat > /etc/sysctl.d/30-ip-forward.conf << EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    sysctl -p /etc/sysctl.d/30-ip-forward.conf
    

    cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f
flush ruleset

table inet usb_router_filter {
  chain forward {
    type filter hook forward priority 0;
    policy drop;
    ct state established,related accept
    iifname "usb*" oifname "${TAILSCALE_INTERFACE}" accept
    iifname "usb*" oifname "${OPENVPN_INTERFACE}" accept
    oifname "usb*" ct state related,established accept
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
    systemctl enable nftables
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
        # Prefer official installer script which handles Debian/Ubuntu/Armbian variants
        if curl -fsSL https://tailscale.com/install.sh | sh; then
            log_info "Tailscale installed via official script"
        else
            log_warn "Tailscale install script failed; attempting apt install from distro repos"
            apt-get update && apt-get install -y tailscale || log_error "Failed to install Tailscale"
        fi
    fi
    
    systemctl enable tailscaled

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
# Config (baked for this device)
USB_NETWORK="192.168.64.0/24"
TAILSCALE_INTERFACE="tailscale0"
OPENVPN_INTERFACE="tun0"

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
echo "NAT (nft) postrouting chain:"
nft list chain ip usb_router_nat postrouting 2>/dev/null || echo "  (no usb_router_nat table)"
echo
echo "Forwarding (nft) forward chain:"
nft list chain inet usb_router_filter forward 2>/dev/null || echo "  (no usb_router_filter table)"
echo
echo "Routing:"
if ip rule show | grep -q "from $USB_NETWORK table usb_vpn"; then
    echo "  USB clients use VPN routing table"
    current_route=$(ip route show table usb_vpn 2>/dev/null | grep default || echo "No default route")
    if echo "$current_route" | grep -q "$TAILSCALE_INTERFACE"; then
        echo "  Active VPN: Tailscale"
    elif echo "$current_route" | grep -q "$OPENVPN_INTERFACE"; then
        echo "  Active VPN: OpenVPN (failover)"
    else
        echo "  Active VPN: None configured"
    fi
else
    echo "  Traffic routed through: Local WAN"
fi
echo ""
echo "VPN Status:"
echo "  Tailscale: $(ip link show $TAILSCALE_INTERFACE &>/dev/null && echo "UP" || echo "DOWN")"
echo "  OpenVPN: $(ip link show $OPENVPN_INTERFACE &>/dev/null && echo "UP" || echo "DOWN")"
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
  echo "  off    - Disable exit node (no routing changes)"
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
    
    log_msg "Switched to Tailscale successfully"
}

switch_to_openvpn() {
    log_msg "Switching USB routing to OpenVPN..."
    
    # Update routing table
    ip route del default table usb_vpn 2>/dev/null || true
    # OpenVPN usually sets up routes automatically, just use the interface
    ip route add default dev $OPENVPN_INTERFACE table usb_vpn
    
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
    setup_system_dns
    setup_time_sync
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

    # Check if reboot is required (for RK3399 boards)
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
    log_info "  usb-router-tailscale       - Switch between local/Tailscale routing"
    log_info "  usb-router-vpn-monitor     - Check VPN failover status"
    log_info "  usb-interface-watchdog     - Check USB interface watchdog"
}

# Run main function
main "$@"