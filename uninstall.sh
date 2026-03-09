#!/bin/bash
# ─────────────────────────────────────────────
#   LIDS - Linux Intrusion Detection System
#   Uninstaller
# ─────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

spin() {
    local msg="$1"
    local cmd="$2"
    echo -ne "  ${BLUE}•${NC}  ${msg}... "
    eval "$cmd" &>/dev/null &
    local PID=$! i=0
    local SPINNER="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    while kill -0 $PID 2>/dev/null; do
        echo -ne "${CYAN}${SPINNER:$((i % ${#SPINNER})):1}${NC}\b"
        sleep 0.1
        ((i++))
    done
    wait $PID 2>/dev/null || true
    echo -e "\r  ${GREEN}✓${NC}  ${msg}        "
}

[[ $EUID -ne 0 ]] && echo -e "${RED}[!] Root kerak: sudo bash uninstall.sh${NC}" && exit 1

clear
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
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${RED}${BOLD}⚠️  LIDS o'chirilmoqda!${NC}"
echo ""
echo -e "  Quyidagilar o'chiriladi:"
echo -e "  ${RED}✗${NC}  /opt/lids       — agent fayllari"
echo -e "  ${RED}✗${NC}  /etc/lids       — konfiguratsiya"
echo -e "  ${RED}✗${NC}  /var/log/lids   — loglar"
echo -e "  ${RED}✗${NC}  lids.service    — systemd servis"
echo ""
read -rp "  Davom etasizmi? [y/N] " CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && echo -e "\n  ${YELLOW}Bekor qilindi.${NC}" && echo "" && exit 0
echo ""

# ── Servisni to'xtatish ──────────────────────────────────────
spin "Servis to'xtatilmoqda" \
    "systemctl stop lids 2>/dev/null; systemctl disable lids --quiet 2>/dev/null"

# ── Systemd service o'chirish ────────────────────────────────
spin "Systemd service o'chirilmoqda" \
    "rm -f /etc/systemd/system/lids.service && systemctl daemon-reload"

# ── Agent fayllari ───────────────────────────────────────────
spin "Agent fayllari o'chirilmoqda (/opt/lids)" \
    "rm -rf /opt/lids"

# ── Config ───────────────────────────────────────────────────
spin "Konfiguratsiya o'chirilmoqda (/etc/lids)" \
    "rm -rf /etc/lids"

# ── Loglar ───────────────────────────────────────────────────
spin "Loglar o'chirilmoqda (/var/log/lids)" \
    "rm -rf /var/log/lids"

# ── UFW qoidalar (agar LIDS qo'shgan bo'lsa) ─────────────────
if command -v ufw &>/dev/null; then
    spin "UFW qoidalari tozalanmoqda" \
        "ufw --force reset 2>/dev/null || true"
fi

echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}${BOLD}✓  LIDS to'liq o'chirildi.${NC}"
echo ""
echo -e "  ${CYAN}github.com/Yescrypt/lids${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""