"""
LIDS Process Monitor
Monitors running processes for suspicious activity
"""

import subprocess
import time
import logging
import os
import re

logger = logging.getLogger('lids.process_monitor')

SUSPICIOUS_NAMES = [
    'xmrig', 'minerd', 'cpuminer', 'cgminer',  # miners
    'masscan', 'zmap',                           # scanners
    'hydra', 'medusa', 'john', 'hashcat',        # crackers
    'msfconsole', 'msfvenom',                    # metasploit
    'empire', 'covenant',                         # C2 frameworks
]

SUSPICIOUS_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/']

# /tmp da ishlashi NORMAL bo'lgan jarayonlar — false positive oldini olish
TMP_WHITELIST_PATTERNS = [
    r'\.X\d+-lock',           # X11 lock files
    r'snap-',                 # Snap packages
    r'systemd-',              # systemd temp files
    r'runtime-',              # User runtime dirs
    r'\.mount_',              # Mount points
    r'chrome',                # Google Chrome
    r'chromium',              # Chromium
    r'firefox',               # Firefox
    r'electron',              # Electron apps
    r'obsidian',              # Obsidian
    r'code',                  # VS Code
    r'telegram',              # Telegram
    r'\.org\.kde\.',          # KDE
    r'MdA',                   # Chrome webview (random tmp)
    r'-webview-',             # Webview processes
    r'\.npm',                 # npm
    r'pip-',                  # pip temp
    r'tmp\d{6,}',             # Generic temp dirs with numbers
    r'java_pid',              # Java
    r'hsperfdata',            # Java HotSpot
    r'\.gnome',               # GNOME
    r'dbus-',                 # DBus
    r'pulse-',                # PulseAudio
    r'\.ICE-unix',            # ICE
]

_tmp_whitelist_re = [re.compile(p) for p in TMP_WHITELIST_PATTERNS]


def _is_tmp_whitelisted(cmdline: str) -> bool:
    """Returns True if this /tmp process is a known legitimate program"""
    for pattern in _tmp_whitelist_re:
        if pattern.search(cmdline):
            return True
    return False


class ProcessMonitor:
    def __init__(self, config, api):
        self.config = config
        self.api = api
        self.interval = 30
        self.seen_alerts = set()
        self.whitelist = set(config.get('whitelist_processes', []))

    def start(self):
        logger.info("Process Monitor started")
        while True:
            try:
                self._scan_processes()
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
            time.sleep(self.interval)

    def _scan_processes(self):
        try:
            result = subprocess.run(['ps', 'auxww'], capture_output=True, text=True)
            for line in result.stdout.splitlines()[1:]:
                parts = line.split(None, 10)
                if len(parts) < 11:
                    continue
                pid = parts[1]
                cmdline = parts[10]
                proc_name = os.path.basename(cmdline.split()[0]) if cmdline.split() else ''

                if proc_name in self.whitelist:
                    continue

                # Check by suspicious name
                for sus in SUSPICIOUS_NAMES:
                    if sus in proc_name.lower() or sus in cmdline.lower():
                        alert_id = f"proc_{sus}_{pid}"
                        if alert_id not in self.seen_alerts:
                            self.seen_alerts.add(alert_id)
                            self._alert_process(proc_name, pid, cmdline, sus)
                        break

                # Check by suspicious path — skip whitelisted patterns
                for sus_path in SUSPICIOUS_PATHS:
                    if cmdline.startswith(sus_path):
                        if _is_tmp_whitelisted(cmdline):
                            break  # Normal process, skip
                        alert_id = f"proc_path_{pid}_{cmdline[:40]}"
                        if alert_id not in self.seen_alerts:
                            self.seen_alerts.add(alert_id)
                            self._alert_tmp_process(proc_name, pid, cmdline)
                        break

        except Exception as e:
            logger.error(f"Process scan error: {e}")

    def _alert_process(self, name, pid, cmdline, reason):
        logger.warning(f"Suspicious process: {name} (PID {pid})")
        self.api.send_alert(
            module='process_monitor',
            severity='critical',
            title=f'🦠 Shubhali jarayon: {name}',
            data={
                'name': name,
                'pid': pid,
                'cmdline': cmdline[:200],
                'reason': reason
            },
            buttons=[
                {'label': '☠️ KILL', 'action': 'kill_process', 'value': pid},
                {'label': '🔍 INFO', 'action': 'process_info', 'value': pid},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': pid},
            ]
        )

    def _alert_tmp_process(self, name, pid, cmdline):
        logger.warning(f"Process from /tmp: {name} (PID {pid}) — {cmdline[:80]}")
        self.api.send_alert(
            module='process_monitor',
            severity='warning',
            title='⚠️ /tmp dan ishga tushgan jarayon',
            data={
                'name': name,
                'pid': pid,
                'path': cmdline[:200]
            },
            buttons=[
                {'label': '☠️ KILL & DELETE', 'action': 'kill_and_delete', 'value': pid},
                {'label': '🔍 INFO', 'action': 'process_info', 'value': pid},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': pid},
            ]
        )