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

                # Check by name
                for sus in SUSPICIOUS_NAMES:
                    if sus in proc_name.lower() or sus in cmdline.lower():
                        alert_id = f"proc_{sus}_{pid}"
                        if alert_id not in self.seen_alerts:
                            self.seen_alerts.add(alert_id)
                            self._alert_process(proc_name, pid, cmdline, sus)
                        break

                # Check by path
                for sus_path in SUSPICIOUS_PATHS:
                    if cmdline.startswith(sus_path):
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
            title=f'⚠️ Suspicious Process: {name}',
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
        self.api.send_alert(
            module='process_monitor',
            severity='warning',
            title=f'⚠️ Process Running from /tmp',
            data={
                'name': name,
                'pid': pid,
                'path': cmdline[:200]
            },
            buttons=[
                {'label': '☠️ KILL & DELETE', 'action': 'kill_and_delete', 'value': pid},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': pid},
            ]
        )
