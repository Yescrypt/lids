"""
LIDS API Client
Sends alerts and receives commands from lids.yescrypt.uz
"""

import requests
import logging
import socket
import platform
import subprocess

logger = logging.getLogger('lids.api')


class APIClient:
    def __init__(self, config):
        self.config = config
        self.base_url = config.get('api_url', 'https://lids.yescrypt.uz')
        self.agent_id = config.get('agent_id')
        self.auth_key = config.get('auth_key')

    def _headers(self):
        return {
            'X-Agent-ID': self.agent_id,
            'X-Auth-Key': self.auth_key,
            'Content-Type': 'application/json'
        }

    def register(self, telegram_user_id, os_name):
        """Register new agent on server"""
        payload = {
            'hostname': socket.gethostname(),
            'os': os_name or platform.platform(),
            'kernel': platform.release(),
            'ip': self._get_local_ip(),
            'telegram_user_id': telegram_user_id
        }
        try:
            resp = requests.post(
                f'{self.base_url}/api/register',
                json=payload,
                timeout=10
            )
            data = resp.json()
            if data.get('agent_id'):
                self.config.set('agent_id', data['agent_id'])
                self.config.set('auth_key', data['auth_key'])
                self.agent_id = data['agent_id']
                self.auth_key = data['auth_key']
                logger.info(f"✅ Registered. Agent ID: {self.agent_id}")
                return True
            else:
                logger.error(f"Registration failed: {data}")
                return False
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False

    def send_alert(self, module: str, severity: str, title: str, data: dict, buttons: list = None):
        """Send alert to server → Telegram"""
        payload = {
            'agent_id': self.agent_id,
            'auth_key': self.auth_key,
            'module': module,
            'severity': severity,   # critical / warning / info
            'title': title,
            'data': data,
            'buttons': buttons or []
        }
        try:
            resp = requests.post(
                f'{self.base_url}/api/alert',
                json=payload,
                headers=self._headers(),
                timeout=10
            )
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Alert send error: {e}")
            return False

    def send_heartbeat(self):
        """Send alive ping to server"""
        try:
            requests.post(
                f'{self.base_url}/api/heartbeat',
                json={'agent_id': self.agent_id, 'auth_key': self.auth_key},
                headers=self._headers(),
                timeout=5
            )
        except Exception:
            pass

    def poll_commands(self):
        """Check for pending commands (block IP, kill process etc.)"""
        try:
            resp = requests.get(
                f'{self.base_url}/api/commands',
                headers=self._headers(),
                timeout=5
            )
            return resp.json().get('commands', [])
        except Exception:
            return []

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except Exception:
            return '127.0.0.1'
