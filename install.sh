#!/bin/bash
# ─────────────────────────────────────────────
#   LIDS - Linux Intrusion Detection System
#   Installer
# ─────────────────────────────────────────────

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

LIDS_DIR="/opt/lids"
LIDS_CONF="/etc/lids"
LIDS_LOG="/var/log/lids"
API_URL="https://lids.yescrypt.uz"
SERVICE_FILE="/etc/systemd/system/lids.service"

echo ""
echo -e "${CYAN}${BOLD}"
echo "                             ██╗     ██╗██████╗ ███████╗"
echo "                             ██║     ██║██╔══██╗██╔════╝"
echo "                             ██║     ██║██║  ██║███████╗"
echo "                             ██║     ██║██║  ██║╚════██║"
echo "                             ███████╗██║██████╔╝███████║"
echo "                             ╚══════╝╚═╝╚═════╝ ╚══════╝"
echo -e "${NC}"
echo -e "                        ${CYAN}${BOLD}  Linux Intrusion Detection System${NC}"
echo -e "  ${CYAN}${NC}GitHub:${NC}${CYAN} https://github.com/Yescrypt/lids${NC}  ${YELLOW}|${NC}  Yordam TG: ${CYAN}https://t.me/anonim_xatbot${NC}"

echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Root check
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Run as root: sudo bash ./install.sh${NC}"
    exit 1
fi

# Detect OS
detect_os() {
    if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
        OS_TYPE="debian"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
        OS_TYPE="arch"
    else
        echo -e "${RED}[!] Unsupported OS${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] Detected OS: $OS_TYPE (${PKG_MANAGER})${NC}"
}

# Install dependencies
install_deps() {
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        apt-get update -qq
        apt-get install -y python3 python3-pip rkhunter chkrootkit iproute2 ufw 2>/dev/null || true
    elif [[ "$PKG_MANAGER" == "pacman" ]]; then
        pacman -Sy --noconfirm python python-pip rkhunter iproute2 ufw 2>/dev/null || true
    fi
    pip3 install requests --break-system-packages -q 2>/dev/null || pip3 install requests -q
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
}

# Get user input
get_input() {
    echo ""
    echo -e "${BOLD}Setup${NC}"
    echo "────────────────────────────"
    
    read -p "  Hostname label [$(hostname)]: " HOST_LABEL
    HOST_LABEL=${HOST_LABEL:-$(hostname)}

    read -p "  OS name [Kali / Parrot / Arch]: " OS_NAME
    OS_NAME=${OS_NAME:-$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')}

    read -p "  Telegram User ID: " TG_USER_ID
    if [[ -z "$TG_USER_ID" ]]; then
        echo -e "${RED}[!] Telegram User ID required${NC}"
        exit 1
    fi

    echo ""
    echo -e "${YELLOW}[*] Registering agent...${NC}"
}

# Register with API
register_agent() {
    RESPONSE=$(curl -s -X POST "$API_URL/api/register" \
        -H "Content-Type: application/json" \
        -d "{
            \"hostname\": \"$HOST_LABEL\",
            \"os\": \"$OS_NAME\",
            \"kernel\": \"$(uname -r)\",
            \"ip\": \"$(hostname -I | awk '{print $1}')\",
            \"telegram_user_id\": \"$TG_USER_ID\"
        }" 2>/dev/null)

    AGENT_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('agent_id',''))" 2>/dev/null)
    AUTH_KEY=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('auth_key',''))" 2>/dev/null)

    if [[ -z "$AGENT_ID" ]]; then
        echo -e "${RED}[!] Registration failed. Check API URL or try again.${NC}"
        echo "    Response: $RESPONSE"
        exit 1
    fi
    echo -e "${GREEN}[✓] Registered. Agent ID: $AGENT_ID${NC}"
}

# Install files
install_files() {
    echo -e "${YELLOW}[*] Installing LIDS...${NC}"
    
    mkdir -p "$LIDS_DIR" "$LIDS_CONF" "$LIDS_LOG"
    cp -r ./agent/* "$LIDS_DIR/"
    
    # Write config
    cat > "$LIDS_CONF/lids.conf" <<EOF
{
    "api_url": "$API_URL",
    "agent_id": "$AGENT_ID",
    "auth_key": "$AUTH_KEY",
    "hostname": "$HOST_LABEL",
    "scan_interval": 30,
    "whitelist_ports": [80, 443, 22, 53],
    "whitelist_processes": ["nmap", "netcat", "nc", "msfconsole"],
    "whitelist_ips": [],
    "log_level": "INFO"
}
EOF
    
    chmod 600 "$LIDS_CONF/lids.conf"
    echo -e "${GREEN}[✓] Files installed${NC}"
}

# Create systemd service
install_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=LIDS - Linux Intrusion Detection System
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 $LIDS_DIR/lids_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable lids
    systemctl start lids
    echo -e "${GREEN}[✓] LIDS service started${NC}"
}

# Main
detect_os
install_deps
get_input
register_agent
install_files
install_service

echo ""
echo -e "${GREEN}${BOLD}  ✅ LIDS installed successfully!${NC}"
echo ""
echo -e "  Status:  ${CYAN}systemctl status lids${NC}"
echo -e "  Logs:    ${CYAN}tail -f /var/log/lids/lids.log${NC}"
echo -e "  Config:  ${CYAN}$LIDS_CONF/lids.conf${NC}"
echo ""
echo -e "  ${BOLD}Telegram:${NC}"
echo -e "  Alertlar ${BOLD}${TG_USER_ID}${NC} ga yuboriladi"
echo -e "  Bot: ${CYAN}@lids_osf_bot${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${YELLOW}Check your Telegram for confirmation message!${NC}"
echo ""
