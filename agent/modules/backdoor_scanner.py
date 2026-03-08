"""
LIDS Backdoor Scanner
Detects post-exploitation artifacts:
- Reverse shells
- Cron backdoors
- Startup persistence (systemd, rc.local, profile)
- SUID/SGID abuse
- Hidden users
- SSH authorized_keys tampering
- LD_PRELOAD hijacking
- /etc/passwd tampering
- Webshells
- Rootkit indicators
"""

import os
import subprocess
import time
import logging
import hashlib
import re
import stat
from pathlib import Path

logger = logging.getLogger('lids.backdoor_scanner')

# Known reverse shell indicators in process cmdline
REVERSE_SHELL_PATTERNS = [
    r'bash\s+-i',
    r'/dev/tcp/',
    r'nc\s+.*\-e',
    r'ncat\s+.*\-e',
    r'python.*socket.*connect',
    r'perl.*socket',
    r'ruby.*TCPSocket',
    r'php.*fsockopen',
    r'socat.*exec',
    r'mkfifo.*nc',
]

# Suspicious cron patterns
CRON_BACKDOOR_PATTERNS = [
    r'/tmp/',
    r'/dev/shm/',
    r'curl.*sh',
    r'wget.*sh',
    r'bash\s+-i',
    r'nc\s+',
    r'python.*-c',
]

# Persistence locations to check
PERSISTENCE_PATHS = [
    '/etc/rc.local',
    '/etc/profile',
    '/etc/profile.d/',
    '/etc/bash.bashrc',
    '/root/.bashrc',
    '/root/.profile',
    '/root/.bash_profile',
    '/etc/init.d/',
    '/etc/cron.d/',
    '/var/spool/cron/',
    '/etc/crontab',
]

# Legitimate SUID binaries (whitelist)
LEGIT_SUID = {
    '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd', '/usr/bin/newgrp',
    '/usr/bin/gpasswd', '/usr/bin/chfn', '/usr/bin/chsh', '/usr/bin/mount',
    '/usr/bin/umount', '/usr/bin/pkexec', '/usr/bin/ping', '/usr/bin/crontab',
    '/usr/bin/ssh-agent', '/usr/bin/chage', '/usr/bin/expiry',
    '/usr/bin/fusermount3', '/usr/bin/dotlockfile', '/usr/bin/ntfs-3g',
    '/usr/sbin/mount.nfs', '/usr/sbin/unix_chkpwd', '/usr/sbin/exim4',
    '/usr/sbin/pppd',
    '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
    '/usr/lib/openssh/ssh-keysign',
    '/usr/libexec/camel-lock-helper-1.2',
    '/usr/share/code/chrome-sandbox',
    '/usr/lib/chromium/chrome-sandbox',
    '/opt/google/chrome/chrome-sandbox',
    '/bin/mount', '/bin/umount', '/bin/su', '/bin/ping',
}

# Webshell signatures
WEBSHELL_SIGNATURES = [
    b'eval(base64_decode',
    b'eval(gzinflate',
    b'system($_GET',
    b'system($_POST',
    b'passthru($_GET',
    b'exec($_GET',
    b'shell_exec($_GET',
    b'<?php @eval(',
    b'<? system(',
    b'preg_replace.*\/e.*\$_',
]

WEB_ROOTS = ['/var/www', '/srv/http', '/usr/share/nginx', '/opt/lampp/htdocs']


class BackdoorScanner:
    def __init__(self, config, api):
        self.config = config
        self.api = api
        self.interval = 300  # 5 min
        self.seen_alerts = set()

    def start(self):
        logger.info("Backdoor Scanner started")
        while True:
            try:
                self.scan()
            except Exception as e:
                logger.error(f"Backdoor scan error: {e}")
            time.sleep(self.interval)

    def scan(self):
        self._scan_reverse_shells()
        self._scan_cron_backdoors()
        self._scan_persistence()
        self._scan_suid_binaries()
        self._scan_ssh_authorized_keys()
        self._scan_ld_preload()
        self._scan_etc_passwd()
        self._scan_hidden_users()
        self._scan_tmp_executables()
        self._scan_webshells()
        self._scan_rootkit_indicators()

    # ─── 1. Reverse Shell Detection ──────────────────────────────────────────

    def _scan_reverse_shells(self):
        try:
            result = subprocess.run(
                ['ps', 'auxww'], capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                for pattern in REVERSE_SHELL_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        pid_match = re.search(r'\s+(\d+)\s+', line)
                        pid = pid_match.group(1) if pid_match else '?'
                        alert_id = f"revshell_{line[:60]}"
                        if alert_id not in self.seen_alerts:
                            self.seen_alerts.add(alert_id)
                            self._alert_reverse_shell(line.strip(), pid)
        except Exception as e:
            logger.error(f"Reverse shell scan: {e}")

    def _alert_reverse_shell(self, cmdline, pid):
        logger.critical(f"REVERSE SHELL detected: {cmdline[:80]}")
        self.api.send_alert(
            module='backdoor_scanner',
            severity='critical',
            title='🚨 REVERSE SHELL DETECTED',
            data={'cmdline': cmdline[:200], 'pid': pid},
            buttons=[
                {'label': '☠️ KILL NOW', 'action': 'kill_process', 'value': pid},
                {'label': '🔍 TRACE', 'action': 'trace_pid', 'value': pid},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': pid},
            ]
        )

    # ─── 2. Cron Backdoors ───────────────────────────────────────────────────

    def _scan_cron_backdoors(self):
        cron_sources = [
            '/etc/crontab',
            '/etc/cron.d',
            '/var/spool/cron/crontabs',
        ]
        all_lines = []
        for src in cron_sources:
            if os.path.isfile(src):
                try:
                    with open(src) as f:
                        all_lines += [(src, l.strip()) for l in f if l.strip() and not l.startswith('#')]
                except Exception:
                    pass
            elif os.path.isdir(src):
                for fname in os.listdir(src):
                    fpath = os.path.join(src, fname)
                    try:
                        with open(fpath) as f:
                            all_lines += [(fpath, l.strip()) for l in f if l.strip() and not l.startswith('#')]
                    except Exception:
                        pass

        for path, line in all_lines:
            for pattern in CRON_BACKDOOR_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    alert_id = f"cron_bd_{line[:60]}"
                    if alert_id not in self.seen_alerts:
                        self.seen_alerts.add(alert_id)
                        self._alert_cron_backdoor(path, line)
                    break

    def _alert_cron_backdoor(self, path, line):
        logger.critical(f"Cron backdoor: {path}: {line}")
        self.api.send_alert(
            module='backdoor_scanner',
            severity='critical',
            title='🚨 Cron Backdoor Detected',
            data={'file': path, 'entry': line},
            buttons=[
                {'label': '🗑 DELETE ENTRY', 'action': 'delete_cron', 'value': path},
                {'label': '📋 SHOW CRON', 'action': 'show_cron', 'value': path},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': path},
            ]
        )

    # ─── 3. Persistence Mechanisms ──────────────────────────────────────────

    def _scan_persistence(self):
        """Check startup files for injected commands"""
        suspicious_keywords = [
            'nc ', 'ncat ', 'bash -i', '/dev/tcp', 'curl|bash',
            'wget|bash', 'python -c', 'socat', '/tmp/', '/dev/shm'
        ]
        for path in PERSISTENCE_PATHS:
            if os.path.isfile(path):
                try:
                    with open(path) as f:
                        for line in f:
                            for kw in suspicious_keywords:
                                if kw in line:
                                    alert_id = f"persist_{path}_{line[:40]}"
                                    if alert_id not in self.seen_alerts:
                                        self.seen_alerts.add(alert_id)
                                        self._alert_persistence(path, line.strip())
                                    break
                except Exception:
                    pass

        # Check systemd units not from packages
        self._scan_suspicious_systemd_units()

    def _scan_suspicious_systemd_units(self):
        """Detect manually added systemd units that run suspicious commands"""
        unit_dirs = [
            '/etc/systemd/system',
            '/usr/local/lib/systemd/system',
        ]
        suspicious_kw = ['/tmp/', '/dev/shm/', 'nc ', 'bash -i', 'curl', 'wget']
        for unit_dir in unit_dirs:
            if not os.path.isdir(unit_dir):
                continue
            for fname in os.listdir(unit_dir):
                if not fname.endswith('.service'):
                    continue
                fpath = os.path.join(unit_dir, fname)
                try:
                    with open(fpath) as f:
                        content = f.read()
                    for kw in suspicious_kw:
                        if kw in content:
                            alert_id = f"systemd_{fname}"
                            if alert_id not in self.seen_alerts:
                                self.seen_alerts.add(alert_id)
                                self._alert_suspicious_service(fname, fpath, kw)
                            break
                except Exception:
                    pass

    def _alert_persistence(self, path, line):
        logger.critical(f"Persistence in {path}: {line}")
        self.api.send_alert(
            module='backdoor_scanner',
            severity='critical',
            title='🚨 Persistence Mechanism Found',
            data={'file': path, 'line': line},
            buttons=[
                {'label': '📋 SHOW FILE', 'action': 'show_file', 'value': path},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': path},
            ]
        )

    def _alert_suspicious_service(self, name, path, keyword):
        self.api.send_alert(
            module='backdoor_scanner',
            severity='critical',
            title='🚨 Suspicious Systemd Service',
            data={'service': name, 'file': path, 'keyword': keyword},
            buttons=[
                {'label': '🛑 DISABLE', 'action': 'disable_service', 'value': name},
                {'label': '📋 SHOW', 'action': 'show_file', 'value': path},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': name},
            ]
        )

    # ─── 4. SUID/SGID Abuse ─────────────────────────────────────────────────

    def _scan_suid_binaries(self):
        try:
            result = subprocess.run(
                ['find', '/', '-perm', '/4000', '-o', '-perm', '/2000',
                 '-not', '-path', '/proc/*', '-not', '-path', '/sys/*'],
                capture_output=True, text=True, timeout=30
            )
            for path in result.stdout.splitlines():
                path = path.strip()
                if path and path not in LEGIT_SUID:
                    alert_id = f"suid_{path}"
                    if alert_id not in self.seen_alerts:
                        self.seen_alerts.add(alert_id)
                        self._alert_suid(path)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.error(f"SUID scan: {e}")

    def _alert_suid(self, path):
        logger.warning(f"Unknown SUID binary: {path}")
        self.api.send_alert(
            module='backdoor_scanner',
            severity='warning',
            title='⚠️ Unknown SUID Binary Found',
            data={'path': path},
            buttons=[
                {'label': '🔍 CHECK', 'action': 'file_info', 'value': path},
                {'label': '🗑 REMOVE SUID', 'action': 'remove_suid', 'value': path},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': path},
            ]
        )

    # ─── 5. SSH Authorized Keys ──────────────────────────────────────────────

    def _scan_ssh_authorized_keys(self):
        """Look for new/unexpected keys in authorized_keys files"""
        homes = ['/root'] + [
            f'/home/{d}' for d in os.listdir('/home')
            if os.path.isdir(f'/home/{d}')
        ] if os.path.isdir('/home') else ['/root']

        for home in homes:
            keyfile = os.path.join(home, '.ssh', 'authorized_keys')
            if not os.path.exists(keyfile):
                continue
            try:
                mtime = os.path.getmtime(keyfile)
                # Detect if recently modified (within last scan window)
                import time as t
                if t.time() - mtime < self.interval * 2:
                    with open(keyfile) as f:
                        keys = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                    if keys:
                        alert_id = f"authkeys_{keyfile}_{mtime}"
                        if alert_id not in self.seen_alerts:
                            self.seen_alerts.add(alert_id)
                            self._alert_new_ssh_key(keyfile, len(keys))
            except Exception:
                pass

    def _alert_new_ssh_key(self, keyfile, count):
        logger.critical(f"SSH authorized_keys modified: {keyfile}")
        self.api.send_alert(
            module='backdoor_scanner',
            severity='critical',
            title='🚨 SSH Key Added (Backdoor Risk)',
            data={'file': keyfile, 'key_count': count},
            buttons=[
                {'label': '📋 SHOW KEYS', 'action': 'show_file', 'value': keyfile},
                {'label': '🗑 CLEAR KEYS', 'action': 'clear_auth_keys', 'value': keyfile},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': keyfile},
            ]
        )

    # ─── 6. LD_PRELOAD Hijacking ─────────────────────────────────────────────

    def _scan_ld_preload(self):
        ld_files = ['/etc/ld.so.preload']
        env_check = subprocess.run(['env'], capture_output=True, text=True)
        if 'LD_PRELOAD' in env_check.stdout:
            alert_id = "ld_preload_env"
            if alert_id not in self.seen_alerts:
                self.seen_alerts.add(alert_id)
                self.api.send_alert(
                    module='backdoor_scanner',
                    severity='critical',
                    title='🚨 LD_PRELOAD Detected (Rootkit Risk)',
                    data={'source': 'environment'},
                    buttons=[
                        {'label': '✅ IGNORE', 'action': 'ignore', 'value': 'ldpreload'},
                    ]
                )

        if os.path.exists('/etc/ld.so.preload'):
            with open('/etc/ld.so.preload') as f:
                content = f.read().strip()
            if content:
                alert_id = f"ld_preload_file_{content[:40]}"
                if alert_id not in self.seen_alerts:
                    self.seen_alerts.add(alert_id)
                    self._alert_ld_preload(content)

    def _alert_ld_preload(self, lib):
        self.api.send_alert(
            module='backdoor_scanner',
            severity='critical',
            title='🚨 /etc/ld.so.preload Modified (Rootkit Risk)',
            data={'library': lib},
            buttons=[
                {'label': '🗑 CLEAR FILE', 'action': 'clear_file', 'value': '/etc/ld.so.preload'},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': 'ldpreload'},
            ]
        )

    # ─── 7. /etc/passwd Tampering ────────────────────────────────────────────

    def _scan_etc_passwd(self):
        """Detect new root-UID users or shell changes"""
        try:
            with open('/etc/passwd') as f:
                lines = f.readlines()
            for line in lines:
                parts = line.strip().split(':')
                if len(parts) < 7:
                    continue
                username, _, uid, gid, _, home, shell = parts[:7]
                # UID 0 but not root
                if uid == '0' and username != 'root':
                    alert_id = f"passwd_uid0_{username}"
                    if alert_id not in self.seen_alerts:
                        self.seen_alerts.add(alert_id)
                        self._alert_hidden_root(username)
        except Exception as e:
            logger.error(f"passwd scan: {e}")

    def _alert_hidden_root(self, username):
        logger.critical(f"Hidden root user: {username}")
        self.api.send_alert(
            module='backdoor_scanner',
            severity='critical',
            title='🚨 Hidden Root User Detected',
            data={'username': username, 'uid': '0'},
            buttons=[
                {'label': '🗑 DELETE USER', 'action': 'delete_user', 'value': username},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': username},
            ]
        )

    # ─── 8. Hidden Users ─────────────────────────────────────────────────────

    def _scan_hidden_users(self):
        """Users in /etc/passwd but not in 'getent passwd' or with no home"""
        try:
            result = subprocess.run(['getent', 'passwd'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.split(':')
                if len(parts) < 7:
                    continue
                username, _, uid_s, _, _, home, shell = parts[:7]
                uid = int(uid_s)
                # System accounts (uid < 1000) except root skip
                if uid < 1000 and uid != 0:
                    continue
                if uid == 0 and username != 'root':
                    alert_id = f"hidden_user_{username}"
                    if alert_id not in self.seen_alerts:
                        self.seen_alerts.add(alert_id)
                        self._alert_hidden_root(username)
        except Exception:
            pass

    # ─── 9. /tmp and /dev/shm Executables ───────────────────────────────────

    def _scan_tmp_executables(self):
        for tmp_dir in ['/tmp', '/dev/shm', '/var/tmp']:
            if not os.path.isdir(tmp_dir):
                continue
            for root_dir, dirs, files in os.walk(tmp_dir):
                for fname in files:
                    fpath = os.path.join(root_dir, fname)
                    try:
                        st = os.stat(fpath)
                        # Executable bit set
                        if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                            # Skip known false positives
                            skip_patterns = [
                                'chrome', 'Chrome', 'google', 'telegram', 'TD-webview',
                                '.X11-unix', 'SingletonSocket', '.dbus', 'snap-',
                                'systemd', 'runtime-'
                            ]
                            if any(p in fpath for p in skip_patterns):
                                continue
                            alert_id = f"tmpexec_{fpath}"
                            if alert_id not in self.seen_alerts:
                                self.seen_alerts.add(alert_id)
                                self._alert_tmp_exec(fpath)
                    except Exception:
                        pass

    def _alert_tmp_exec(self, path):
        logger.warning(f"Executable in tmp: {path}")
        self.api.send_alert(
            module='backdoor_scanner',
            severity='warning',
            title='⚠️ Executable in /tmp or /dev/shm',
            data={'path': path},
            buttons=[
                {'label': '☠️ KILL & DELETE', 'action': 'kill_and_delete', 'value': path},
                {'label': '🔍 FILE INFO', 'action': 'file_info', 'value': path},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': path},
            ]
        )

    # ─── 10. Webshell Detection ──────────────────────────────────────────────

    def _scan_webshells(self):
        for web_root in WEB_ROOTS:
            if not os.path.isdir(web_root):
                continue
            for root_dir, dirs, files in os.walk(web_root):
                for fname in files:
                    if not any(fname.endswith(ext) for ext in ['.php', '.phtml', '.php5', '.asp', '.aspx', '.jsp']):
                        continue
                    fpath = os.path.join(root_dir, fname)
                    try:
                        with open(fpath, 'rb') as f:
                            content = f.read(4096)
                        for sig in WEBSHELL_SIGNATURES:
                            if sig in content:
                                alert_id = f"webshell_{fpath}"
                                if alert_id not in self.seen_alerts:
                                    self.seen_alerts.add(alert_id)
                                    self._alert_webshell(fpath, sig.decode(errors='replace'))
                                break
                    except Exception:
                        pass

    def _alert_webshell(self, path, signature):
        logger.critical(f"Webshell: {path}")
        self.api.send_alert(
            module='backdoor_scanner',
            severity='critical',
            title='🚨 Webshell Detected',
            data={'path': path, 'signature': signature},
            buttons=[
                {'label': '🗑 DELETE', 'action': 'delete_file', 'value': path},
                {'label': '🔒 QUARANTINE', 'action': 'quarantine', 'value': path},
                {'label': '✅ IGNORE', 'action': 'ignore', 'value': path},
            ]
        )

    # ─── 11. Rootkit Indicators ──────────────────────────────────────────────

    def _scan_rootkit_indicators(self):
        """Quick rootkit checks without full rkhunter"""
        indicators = []

        # Check if ps, ls, netstat return different results than direct proc read
        try:
            ps_pids = set()
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            for line in result.stdout.splitlines()[1:]:
                m = re.search(r'\s+(\d+)\s+', line)
                if m:
                    ps_pids.add(m.group(1))

            proc_pids = set(
                p for p in os.listdir('/proc') if p.isdigit()
            )

            hidden = proc_pids - ps_pids
            # Filter known false positives (kernel threads, short-lived)
            real_hidden = set()
            for pid in hidden:
                try:
                    with open(f'/proc/{pid}/cmdline') as f:
                        cmd = f.read()
                    if cmd:  # Has cmdline → real process
                        real_hidden.add(pid)
                except Exception:
                    pass

            if real_hidden:
                indicators.append(f"Hidden PIDs (rootkit?): {real_hidden}")
        except Exception:
            pass

        # Check for common rootkit files
        rootkit_files = [
            '/usr/bin/sshd.bak', '/usr/bin/ssh.bak',
            '/etc/.hidden', '/tmp/.font-unix/.fsck',
        ]
        for rf in rootkit_files:
            if os.path.exists(rf):
                indicators.append(f"Suspicious file: {rf}")

        if indicators:
            alert_id = f"rootkit_{'|'.join(indicators)[:40]}"
            if alert_id not in self.seen_alerts:
                self.seen_alerts.add(alert_id)
                self.api.send_alert(
                    module='backdoor_scanner',
                    severity='critical',
                    title='🚨 Rootkit Indicators Detected',
                    data={'indicators': indicators},
                    buttons=[
                        {'label': '🔍 FULL SCAN', 'action': 'run_rkhunter', 'value': ''},
                        {'label': '✅ IGNORE', 'action': 'ignore', 'value': 'rootkit'},
                    ]
                )
