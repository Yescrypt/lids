"""
LIDS SSH Monitor
Checks SSH config weaknesses and service status
"""

import subprocess
import time
import logging
import os

logger = logging.getLogger('lids.ssh_monitor')

SSHD_CONFIG = '/etc/ssh/sshd_config'


class SSHMonitor:
    def __init__(self, config, api):
        self.config = config
        self.api = api
        self.alerted = False
        self.interval = 3600  # check every hour

    def start(self):
        logger.info("SSH Monitor started")
        while True:
            self.check()
            time.sleep(self.interval)

    def check(self):
        ssh_running = self._is_ssh_running()
        weaknesses = self._check_config()

        if ssh_running and weaknesses:
            self._alert_weaknesses(weaknesses)
        elif ssh_running and not self.alerted:
            self._alert_ssh_active()
            self.alerted = True

    def _is_ssh_running(self):
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'ssh'],
                capture_output=True, text=True
            )
            return result.stdout.strip() == 'active'
        except Exception:
            # Try sshd
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', 'sshd'],
                    capture_output=True, text=True
                )
                return result.stdout.strip() == 'active'
            except Exception:
                return False

    def _check_config(self):
        """Returns list of weak configurations"""
        weaknesses = []
        if not os.path.exists(SSHD_CONFIG):
            return weaknesses

        with open(SSHD_CONFIG, 'r') as f:
            lines = f.readlines()

        config = {}
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    config[parts[0].lower()] = parts[1].strip().lower()

        if config.get('permitrootlogin', 'prohibit-password') in ['yes', 'without-password']:
            weaknesses.append('PermitRootLogin: yes')

        if config.get('passwordauthentication', 'yes') == 'yes':
            weaknesses.append('PasswordAuthentication: yes (brute force risk)')

        if config.get('permitemptypasswords', 'no') == 'yes':
            weaknesses.append('PermitEmptyPasswords: yes (CRITICAL)')

        if config.get('x11forwarding', 'no') == 'yes':
            weaknesses.append('X11Forwarding: yes (info leak)')

        # Check if running on default port
        port = config.get('port', '22')
        if port == '22':
            weaknesses.append('Port: 22 (default, high scan exposure)')

        return weaknesses

    def _alert_weaknesses(self, weaknesses):
        logger.warning(f"SSH weaknesses found: {weaknesses}")
        self.api.send_alert(
            module='ssh_monitor',
            severity='warning',
            title='🔑 Weak SSH Configuration',
            data={
                'weaknesses': weaknesses,
                'config_file': SSHD_CONFIG
            },
            buttons=[
                {'label': '🛡 HARDEN SSH', 'action': 'harden_ssh', 'value': ''},
                {'label': '🛑 STOP SSH', 'action': 'stop_ssh', 'value': ''},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': 'ssh'},
            ]
        )

    def _alert_ssh_active(self):
        logger.info("SSH is active, sending reminder")
        self.api.send_alert(
            module='ssh_monitor',
            severity='info',
            title='ℹ️ SSH Service Active',
            data={'message': 'SSH is running. Disable if not needed.'},
            buttons=[
                {'label': '🛑 STOP SSH', 'action': 'stop_ssh', 'value': ''},
                {'label': '🔒 DISABLE SSH', 'action': 'disable_ssh', 'value': ''},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': 'ssh'},
            ]
        )
