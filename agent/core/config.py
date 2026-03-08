"""
LIDS Config - reads from /etc/lids/lids.conf
"""

import json
import os

CONFIG_PATH = '/etc/lids/lids.conf'

DEFAULT_CONFIG = {
    "api_url": "https://lids.yescrypt.uz",
    "agent_id": "",
    "auth_key": "",
    "hostname": "",
    "scan_interval": 30,
    "whitelist_ports": [80, 443, 22, 53],
    "whitelist_processes": ["nmap", "netcat", "nc", "msfconsole"],
    "whitelist_ips": [],
    "log_level": "INFO"
}


class Config:
    def __init__(self):
        self.data = self._load()

    def _load(self):
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        return DEFAULT_CONFIG.copy()

    def save(self):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(self.data, f, indent=2)

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        self.save()
