"""
LIDS API Client
Sends alerts and receives commands from lids.yescrypt.uz
"""

import requests
import logging
import socket
import platform
import json

logger = logging.getLogger('lids.api')


class APIClient:
    def __init__(self, config):
        self.config = config
        self.base_url = config.get('api_url', 'https://lids.yescrypt.uz')
        self.agent_id = config.get('agent_id')
        self.auth_key = config.get('auth_key')

    def _headers(self):
        """Headers for all agent requests"""
        return {
            'Content-Type': 'application/json',
            'X-Agent-ID': self.agent_id or '',
            'X-Auth-Key': self.auth_key or '',
            'X-Lids-Agent': 'yes',
        }

    def _register_headers(self):
        """Headers for register (no agent_id yet)"""
        return {
            'Content-Type': 'application/json',
            'X-Lids-Agent': 'yes',
        }

    def register(self, telegram_user_id, os_name):
        """Register new agent on server"""
        payload = {
            'hostname': socket.gethostname(),
            'os': os_name or platform.platform(),
            'kernel': platform.release(),
            'ip': self._get_local_ip(),
            'telegram_user_id': str(telegram_user_id),
        }
        try:
            resp = requests.post(
                f'{self.base_url}/api/register',
                json=payload,
                headers=self._register_headers(),
                timeout=10,
                verify=True,
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get('agent_id'):
                self.config.set('agent_id', data['agent_id'])
                self.config.set('auth_key', data['auth_key'])
                self.agent_id = data['agent_id']
                self.auth_key = data['auth_key']
                logger.info(f"Registered. Agent ID: {self.agent_id}")
                return True
            else:
                logger.error(f"Registration failed: {data}")
                return False

        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error: {e}")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            return False
        except requests.exceptions.Timeout:
            logger.error("Registration timed out")
            return False
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False

    def send_alert(self, module: str, severity: str, title: str, data: dict, buttons: list = None):
        """Send alert to server -> Telegram"""
        if not self.agent_id or not self.auth_key:
            logger.warning("send_alert: agent not registered yet")
            return False

        safe_data = {}
        for k, v in (data or {}).items():
            if isinstance(v, (list, dict)):
                safe_data[str(k)] = v
            else:
                safe_data[str(k)] = str(v)[:512]

        payload = {
            'agent_id': self.agent_id,
            'auth_key': self.auth_key,
            'module': str(module)[:64],
            'severity': severity if severity in ('critical', 'warning', 'info') else 'info',
            'title': str(title)[:256],
            'data': safe_data,
            'buttons': buttons or [],
        }
        try:
            resp = requests.post(
                f'{self.base_url}/api/alert',
                json=payload,
                headers=self._headers(),
                timeout=10,
                verify=True,
            )
            if resp.status_code == 200:
                return True
            elif resp.status_code == 429:
                logger.warning("Alert rate limit hit")
                return False
            elif resp.status_code == 401:
                logger.error("Alert rejected: invalid credentials")
                return False
            else:
                logger.error(f"Alert failed: {resp.status_code} {resp.text[:200]}")
                return False

        except requests.exceptions.Timeout:
            logger.warning("Alert timed out")
            return False
        except Exception as e:
            logger.error(f"Alert send error: {e}")
            return False

    def send_heartbeat(self):
        """Send alive ping to server"""
        if not self.agent_id:
            return
        payload = {
            'agent_id': self.agent_id,
            'auth_key': self.auth_key,
        }
        try:
            requests.post(
                f'{self.base_url}/api/heartbeat',
                json=payload,
                headers=self._headers(),
                timeout=5,
                verify=True,
            )
        except Exception:
            pass

    def poll_commands(self):
        """Check for pending commands (block IP, kill process etc.)"""
        if not self.agent_id:
            return []
        try:
            resp = requests.get(
                f'{self.base_url}/api/commands',
                params={
                    'agent_id': self.agent_id,
                    'auth_key': self.auth_key,
                },
                headers=self._headers(),
                timeout=5,
                verify=True,
            )
            if resp.status_code == 200:
                return resp.json().get('commands', [])
            return []
        except Exception:
            return []

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'