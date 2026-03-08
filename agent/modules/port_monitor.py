"""
LIDS Port Monitor
Detects newly opened ports and alerts
"""

import subprocess
import time
import logging
import re

logger = logging.getLogger('lids.port_monitor')

SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite backdoor",
    6666: "Common RAT",
    9999: "Common backdoor",
    12345: "NetBus trojan",
    54321: "Back Orifice",
    5555: "Android ADB / backdoor",
    2222: "Alt SSH / backdoor",
    8888: "Common reverse shell",
    3333: "Common reverse shell",
}


class PortMonitor:
    def __init__(self, config, api):
        self.config = config
        self.api = api
        self.known_ports = set()
        self.interval = config.get('scan_interval', 30)
        self.whitelist = set(config.get('whitelist_ports', [80, 443, 22, 53]))

    def get_open_ports(self):
        """Returns dict of {port: {process, pid, proto}}"""
        ports = {}
        try:
            result = subprocess.run(
                ['ss', '-tulnp'],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 5:
                    continue
                proto = parts[0]
                local_addr = parts[4]

                # Extract port
                port_match = re.search(r':(\d+)$', local_addr)
                if not port_match:
                    continue
                port = int(port_match.group(1))

                # Extract process info
                proc_info = line.split('users:')[-1] if 'users:' in line else ''
                pid_match = re.search(r'pid=(\d+)', proc_info)
                name_match = re.search(r'"([^"]+)"', proc_info)

                ports[port] = {
                    'proto': proto,
                    'pid': pid_match.group(1) if pid_match else '?',
                    'process': name_match.group(1) if name_match else '?'
                }
        except Exception as e:
            logger.error(f"Port scan error: {e}")
        return ports

    def start(self):
        logger.info("Port Monitor started")
        # Initial baseline
        self.known_ports = set(self.get_open_ports().keys())
        
        while True:
            time.sleep(self.interval)
            try:
                current = self.get_open_ports()
                current_set = set(current.keys())

                # New ports
                new_ports = current_set - self.known_ports
                for port in new_ports:
                    if port in self.whitelist:
                        continue
                    info = current[port]
                    self._alert_new_port(port, info)

                self.known_ports = current_set

            except Exception as e:
                logger.error(f"Port monitor error: {e}")

    def _alert_new_port(self, port, info):
        severity = 'critical' if port in SUSPICIOUS_PORTS else 'warning'
        
        note = SUSPICIOUS_PORTS.get(port, "")
        note_text = f"\n⚠️ Known: {note}" if note else ""

        logger.warning(f"New port detected: {port} ({info['process']})")

        self.api.send_alert(
            module='port_monitor',
            severity=severity,
            title='🔌 New Port Opened',
            data={
                'port': port,
                'proto': info['proto'],
                'process': info['process'],
                'pid': info['pid'],
                'note': note
            },
            buttons=[
                {'label': '🔥 KILL PROCESS', 'action': 'kill_process', 'value': info['pid']},
                {'label': '🚫 BLOCK PORT', 'action': 'block_port', 'value': str(port)},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': str(port)},
            ]
        )
