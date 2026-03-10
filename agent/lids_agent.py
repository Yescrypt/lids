#!/usr/bin/env python3
"""
LIDS - Linux Intrusion Detection System
Main agent entry point
"""

import time
import threading
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import Config
from core.api_client import APIClient
from modules.port_monitor import PortMonitor
from modules.ssh_monitor import SSHMonitor
from modules.log_monitor import LogMonitor
from modules.process_monitor import ProcessMonitor
from modules.backdoor_scanner import BackdoorScanner
from modules.malware_scan import MalwareScan
from modules.command_executor import CommandExecutor

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(name)s: %(message)s',
    handlers=[
        logging.FileHandler('/var/log/lids/lids.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('LIDS')


class LIDSAgent:
    def __init__(self):
        self.config = Config()
        self.api = APIClient(self.config)

        self.modules = [
            PortMonitor(self.config, self.api),
            SSHMonitor(self.config, self.api),
            LogMonitor(self.config, self.api),
            ProcessMonitor(self.config, self.api),
            BackdoorScanner(self.config, self.api),
            MalwareScan(self.config, self.api),
            CommandExecutor(self.config, self.api),   # ← polls & executes commands
        ]

    def run(self):
        logger.info("🛡 LIDS Agent starting...")
        self.api.send_heartbeat()

        threads = []
        for module in self.modules:
            t = threading.Thread(target=module.start, daemon=True)
            t.start()
            threads.append(t)
            logger.info(f"✅ Module started: {module.__class__.__name__}")

        while True:
            try:
                self.api.send_heartbeat()
                time.sleep(60)
            except KeyboardInterrupt:
                logger.info("LIDS Agent stopped.")
                break


if __name__ == '__main__':
    agent = LIDSAgent()
    agent.run()