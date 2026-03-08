"""
LIDS Firewall Integration
Supports iptables and ufw
"""

import subprocess
import logging
import shutil
import threading
import time

logger = logging.getLogger('lids.firewall')


class Firewall:
    def __init__(self):
        self.backend = self._detect_backend()
        self._timers = {}

    def _detect_backend(self):
        if shutil.which('ufw'):
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
            if 'active' in result.stdout.lower():
                return 'ufw'
        if shutil.which('iptables'):
            return 'iptables'
        return None

    def block_ip(self, ip: str, duration_seconds: int = None):
        """Block an IP. If duration given, auto-unblock after timeout."""
        logger.info(f"Blocking IP {ip} via {self.backend}")
        if self.backend == 'ufw':
            subprocess.run(['ufw', 'deny', 'from', ip, 'to', 'any'], check=True)
        elif self.backend == 'iptables':
            subprocess.run(
                ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True
            )
        else:
            logger.error("No firewall backend available")
            return False

        if duration_seconds:
            t = threading.Timer(duration_seconds, self.unblock_ip, args=[ip])
            t.daemon = True
            t.start()
            self._timers[ip] = t
            logger.info(f"IP {ip} will be unblocked in {duration_seconds}s")

        return True

    def unblock_ip(self, ip: str):
        logger.info(f"Unblocking IP {ip}")
        if self.backend == 'ufw':
            subprocess.run(['ufw', 'delete', 'deny', 'from', ip, 'to', 'any'])
        elif self.backend == 'iptables':
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])

    def block_port(self, port: int):
        logger.info(f"Blocking port {port}")
        if self.backend == 'ufw':
            subprocess.run(['ufw', 'deny', str(port)])
        elif self.backend == 'iptables':
            subprocess.run(
                ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'],
                check=True
            )

    def kill_process(self, pid: str):
        try:
            subprocess.run(['kill', '-9', pid], check=True)
            logger.info(f"Killed PID {pid}")
            return True
        except Exception as e:
            logger.error(f"Kill {pid}: {e}")
            return False

    def remove_suid(self, path: str):
        try:
            subprocess.run(['chmod', '-s', path], check=True)
            return True
        except Exception as e:
            logger.error(f"Remove SUID {path}: {e}")
            return False
