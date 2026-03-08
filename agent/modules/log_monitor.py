"""
LIDS Log Monitor
Detects brute force, sudo abuse, failed logins from journald / auth.log
"""

import subprocess
import time
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger('lids.log_monitor')

BRUTE_THRESHOLD = 5      # attempts before alert
BRUTE_WINDOW_SEC = 120   # within 2 minutes


class LogMonitor:
    def __init__(self, config, api):
        self.config = config
        self.api = api
        self.interval = 15
        self.seen_events = set()
        self.ssh_attempts = defaultdict(list)  # ip -> [timestamps]
        self.last_cursor = None

    def start(self):
        logger.info("Log Monitor started")
        while True:
            try:
                self._check_journal()
                self._check_auth_log()
                self._analyze_brute_force()
            except Exception as e:
                logger.error(f"Log monitor error: {e}")
            time.sleep(self.interval)

    def _check_journal(self):
        cmd = ['journalctl', '-u', 'ssh', '-u', 'sshd', '-n', '50', '--no-pager', '-o', 'short']
        if self.last_cursor:
            cmd.extend(['--after-cursor', self.last_cursor])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                self._parse_auth_line(line)
        except Exception as e:
            logger.debug(f"Journal read: {e}")

    def _check_auth_log(self):
        """Fallback: read /var/log/auth.log"""
        auth_files = ['/var/log/auth.log', '/var/log/secure']
        for path in auth_files:
            try:
                result = subprocess.run(
                    ['tail', '-n', '100', path],
                    capture_output=True, text=True
                )
                for line in result.stdout.splitlines():
                    self._parse_auth_line(line)
                break
            except Exception:
                continue

    def _parse_auth_line(self, line):
        # SSH Failed password
        m = re.search(r'Failed password for (?:invalid user )?(\S+) from ([\d.]+)', line)
        if m:
            user, ip = m.group(1), m.group(2)
            event_id = f"fail_{ip}_{line[-20:]}"
            if event_id not in self.seen_events:
                self.seen_events.add(event_id)
                self.ssh_attempts[ip].append(datetime.now())

        # Root login success
        m = re.search(r'Accepted \w+ for root from ([\d.]+)', line)
        if m:
            ip = m.group(1)
            event_id = f"root_login_{ip}_{line[-20:]}"
            if event_id not in self.seen_events:
                self.seen_events.add(event_id)
                self._alert_root_login(ip)

        # sudo
        m = re.search(r'sudo.*COMMAND=(.*)', line)
        if m:
            cmd = m.group(1).strip()
            if any(x in cmd for x in ['/bin/bash', '/bin/sh', 'chmod 777', 'chmod +s']):
                event_id = f"sudo_{cmd}_{line[-20:]}"
                if event_id not in self.seen_events:
                    self.seen_events.add(event_id)
                    self._alert_sudo_abuse(cmd)

        # New cron job added
        if 'crontab' in line.lower() and 'REPLACE' in line.upper():
            event_id = f"cron_{line[-30:]}"
            if event_id not in self.seen_events:
                self.seen_events.add(event_id)
                self._alert_cron_change(line)

    def _analyze_brute_force(self):
        now = datetime.now()
        window = timedelta(seconds=BRUTE_WINDOW_SEC)

        for ip, timestamps in list(self.ssh_attempts.items()):
            recent = [t for t in timestamps if now - t < window]
            self.ssh_attempts[ip] = recent

            if len(recent) >= BRUTE_THRESHOLD:
                alert_id = f"brute_{ip}_{len(recent)}"
                if alert_id not in self.seen_events:
                    self.seen_events.add(alert_id)
                    self._alert_brute_force(ip, len(recent))

    def _alert_brute_force(self, ip, count):
        logger.warning(f"Brute force detected from {ip}: {count} attempts")
        self.api.send_alert(
            module='log_monitor',
            severity='critical',
            title='🚨 SSH Brute Force Attack',
            data={
                'ip': ip,
                'attempts': count,
                'window': f'{BRUTE_WINDOW_SEC}s'
            },
            buttons=[
                {'label': '🚫 BLOCK IP', 'action': 'block_ip', 'value': ip},
                {'label': '🔍 WHOIS', 'action': 'whois', 'value': ip},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': ip},
            ]
        )

    def _alert_root_login(self, ip):
        logger.warning(f"Root login from {ip}")
        self.api.send_alert(
            module='log_monitor',
            severity='critical',
            title='🚨 Root Login Detected',
            data={'ip': ip},
            buttons=[
                {'label': '🚫 BLOCK IP', 'action': 'block_ip', 'value': ip},
                {'label': '🔍 WHOIS', 'action': 'whois', 'value': ip},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': ip},
            ]
        )

    def _alert_sudo_abuse(self, cmd):
        logger.warning(f"Suspicious sudo: {cmd}")
        self.api.send_alert(
            module='log_monitor',
            severity='critical',
            title='⚠️ Suspicious sudo Command',
            data={'command': cmd},
            buttons=[
                {'label': '✅ OK', 'action': 'ignore', 'value': 'sudo'},
            ]
        )

    def _alert_cron_change(self, line):
        self.api.send_alert(
            module='log_monitor',
            severity='warning',
            title='⚠️ Crontab Modified',
            data={'line': line},
            buttons=[
                {'label': '📋 SHOW CRON', 'action': 'show_cron', 'value': ''},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': 'cron'},
            ]
        )
