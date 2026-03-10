#!/usr/bin/env python3
"""
LIDS Command Executor
Polls server every 10s, executes commands, supports fail2ban + duration-based blocking.
"""

import subprocess, logging, os, time, shutil, threading, re
logger = logging.getLogger('lids.executor')

POLL_INTERVAL = 10

def _dur_label(sec):
    if sec <= 0: return "Butunlay"
    if sec < 3600: return f"{sec//60} daqiqa"
    if sec < 86400: return f"{sec//3600} soat"
    return f"{sec//86400} kun"


class CommandExecutor:
    def __init__(self, config, api):
        self.config = config
        self.api    = api
        self.use_fail2ban = bool(shutil.which('fail2ban-client'))

    def start(self):
        logger.info(f"Command Executor started (fail2ban: {self.use_fail2ban})")
        while True:
            try:
                for cmd in self.api.poll_commands():
                    self._execute(cmd)
            except Exception as e:
                logger.error(f"Executor loop: {e}")
            time.sleep(POLL_INTERVAL)

    def _execute(self, cmd):
        action = cmd.get('action','')
        value  = cmd.get('value','')
        cid    = cmd.get('id','?')
        logger.info(f"[{cid}] {action} = {value!r}")
        handlers = {
            'block_ip':        self._block_ip,
            'unblock_ip':      self._unblock_ip,
            'block_port':      self._block_port,
            'kill_process':    self._kill_process,
            'kill_and_delete': self._kill_and_delete,
            'delete_file':     self._delete_file,
            'quarantine':      self._quarantine,
            'remove_suid':     self._remove_suid,
            'harden_ssh':      self._harden_ssh,
            'stop_ssh':        self._stop_ssh,
            'start_ssh':       self._start_ssh,
            'disable_ssh':     self._disable_ssh,
            'clear_auth_keys': self._clear_auth_keys,
            'delete_user':     self._delete_user,
            'disable_service': self._disable_service,
            'delete_cron':     self._delete_cron,
            'run_full_scan':   self._run_full_scan,
            'run_rkhunter':    self._run_rkhunter,
            'ignore':          lambda v: None,
        }
        h = handlers.get(action)
        if h:
            try: h(value)
            except Exception as e:
                logger.error(f"[{cid}] {action} FAILED: {e}")
                self.api.send_alert(module='executor', severity='warning',
                    title='⚠️ Buyruq bajarilmadi',
                    data={'action': action, 'error': str(e)}, buttons=[])
        else:
            logger.warning(f"Unknown action: {action}")

    def _alert(self, title, data):
        self.api.send_alert(module='executor', severity='info',
                            title=title, data=data, buttons=[])

    # ── Block IP ──────────────────────────────────────────────────────────────

    def _block_ip(self, value: str):
        """value format: "IP|duration_seconds"  (duration 0 = forever)"""
        if '|' in value:
            ip, dur_str = value.rsplit('|', 1)
            try: dur_sec = int(dur_str)
            except ValueError: dur_sec = 0
        else:
            ip, dur_sec = value, 0

        _validate_ip(ip)
        label = _dur_label(dur_sec)

        if self.use_fail2ban:
            try:
                _run(['fail2ban-client', 'set', 'sshd', 'banip', ip])
                logger.info(f"fail2ban banned {ip}")
                if dur_sec > 0:
                    threading.Timer(dur_sec, self._unblock_ip, args=[ip]).start()
                self._alert('🚫 IP Bloklandi (fail2ban)',
                    {'ip': ip, 'muddat': label, 'usul': 'fail2ban'})
                return
            except Exception as e:
                logger.warning(f"fail2ban failed, falling back: {e}")

        if shutil.which('ufw'):
            _run(['ufw', 'deny', 'from', ip, 'to', 'any'])
        else:
            _run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'])

        if dur_sec > 0:
            threading.Timer(dur_sec, self._unblock_ip, args=[ip]).start()

        self._alert('🚫 IP Bloklandi',
            {'ip': ip, 'muddat': label,
             'usul': 'ufw' if shutil.which('ufw') else 'iptables'})

    def _unblock_ip(self, ip: str):
        _validate_ip(ip)
        if self.use_fail2ban:
            try:
                _run(['fail2ban-client', 'set', 'sshd', 'unbanip', ip])
                logger.info(f"fail2ban unbanned {ip}")
            except Exception: pass
        try:
            _run(['ufw', 'delete', 'deny', 'from', ip, 'to', 'any'], check=False)
        except Exception: pass
        try:
            _run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=False)
        except Exception: pass
        self._alert('🔓 IP Blokdan Chiqarildi', {'ip': ip})

    def _block_port(self, port_str: str):
        port = int(port_str)
        assert 1 <= port <= 65535
        if shutil.which('ufw'):
            _run(['ufw', 'deny', str(port)])
        else:
            _run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'])
        self._alert('🔥 Port Bloklandi', {'port': port})

    # ── Process ──────────────────────────────────────────────────────────────

    def _kill_process(self, pid: str):
        pid = str(int(pid))
        _run(['kill', '-9', pid])
        self._alert("☠️ Jarayon O'ldirildi", {'pid': pid})

    def _kill_and_delete(self, value: str):
        """
        value can be:
          - a PID (integer string): kill it and delete its /tmp exe
          - a file path (starts with /): kill by exe match and delete
        """
        pid = None
        exe = None

        if value.startswith('/'):
            # value is a file path — find and kill the process using it
            exe = value
            try:
                r = subprocess.run(['pgrep', '-f', os.path.basename(exe)],
                                   capture_output=True, text=True)
                pids = r.stdout.strip().splitlines()
                for p in pids:
                    try:
                        real_exe = os.readlink(f'/proc/{p.strip()}/exe')
                        if real_exe == exe:
                            pid = p.strip()
                            break
                    except Exception:
                        pass
                if not pid and pids:
                    pid = pids[0].strip()
            except Exception as e:
                logger.warning(f"pgrep failed: {e}")
        else:
            # value is a PID
            try:
                pid = str(int(value))
                try:
                    exe = os.readlink(f'/proc/{pid}/exe')
                except Exception:
                    pass
            except ValueError:
                logger.error(f"kill_and_delete: invalid value {value!r}")
                self.api.send_alert(module='executor', severity='warning',
                    title='⚠️ kill_and_delete xato',
                    data={'value': value, 'error': 'PID yoki path kerak'}, buttons=[])
                return

        # Kill
        killed = False
        if pid:
            try:
                _run(['kill', '-9', pid], check=False)
                killed = True
                logger.info(f"Killed PID {pid}")
            except Exception as e:
                logger.warning(f"Kill {pid}: {e}")

        # Delete
        deleted = False
        if exe and os.path.exists(exe):
            safe_prefixes = ('/tmp', '/dev/shm', '/var/tmp', '/run')
            if any(exe.startswith(p) for p in safe_prefixes):
                try:
                    os.remove(exe)
                    deleted = True
                    logger.info(f"Deleted {exe}")
                except Exception as e:
                    logger.warning(f"Delete {exe}: {e}")
            else:
                logger.warning(f"kill_and_delete: refusing to delete {exe} (not in tmp)")

        self._alert("☠️ O'ldirildi va O'chirildi", {
            'pid':       pid or 'topilmadi',
            'fayl':      exe or 'topilmadi',
            "o'chirildi": str(deleted),
            "o'ldirildi": str(killed),
        })

    def _delete_file(self, path: str):
        _vpath(path); os.remove(path)
        self._alert("🗑 Fayl O'chirildi", {'path': path})

    def _quarantine(self, path: str):
        _vpath(path)
        qd = '/var/quarantine'; os.makedirs(qd, exist_ok=True)
        dest = os.path.join(qd, os.path.basename(path))
        shutil.move(path, dest); os.chmod(dest, 0o000)
        self._alert('🔒 Karantinga Olindi', {'from': path, 'to': dest})

    def _remove_suid(self, path: str):
        _vpath(path); _run(['chmod', '-s', path])
        self._alert('🔒 SUID Olib Tashlandi', {'path': path})

    # ── SSH ──────────────────────────────────────────────────────────────────

    def _harden_ssh(self, _val):
        cfg = '/etc/ssh/sshd_config'
        hardening = {
            'PasswordAuthentication': 'no',
            'PermitRootLogin':        'no',
            'X11Forwarding':          'no',
            'PermitEmptyPasswords':   'no',
            'MaxAuthTries':           '3',
            'LoginGraceTime':         '30',
        }
        with open(cfg) as f: lines = f.readlines()
        new_lines, replaced, applied = [], set(), []
        for line in lines:
            s = line.strip()
            if not s or s.startswith('#'):
                new_lines.append(line); continue
            parts = s.split(None, 1)
            key   = parts[0]
            if key in hardening:
                old = parts[1] if len(parts) > 1 else ''
                nw  = hardening[key]
                if old.lower() != nw.lower():
                    new_lines.append(f"{key} {nw}\n")
                    applied.append(f"{key}: {old!r} → {nw!r}")
                else:
                    new_lines.append(line)
                replaced.add(key)
            else:
                new_lines.append(line)
        for k, v in hardening.items():
            if k not in replaced:
                new_lines.append(f"{k} {v}\n")
                applied.append(f"{k}: (yo'q) → {v!r}")
        with open(cfg + '.lids_bak', 'w') as f: f.writelines(lines)
        with open(cfg, 'w') as f: f.writelines(new_lines)
        _run(['systemctl', 'restart', 'ssh'],  check=False)
        _run(['systemctl', 'restart', 'sshd'], check=False)
        changes = '\n'.join(applied) if applied else "Allaqachon xavfsiz"
        self._alert('🛡 SSH Hardened', {"o'zgartirildi": changes, 'backup': cfg+'.lids_bak'})

    def _stop_ssh(self, _):
        _run(['systemctl', 'stop', 'ssh'],  check=False)
        _run(['systemctl', 'stop', 'sshd'], check=False)
        self._alert("🛑 SSH To'xtatildi", {'status': 'stopped'})

    def _start_ssh(self, _):
        started = False
        for svc in ['ssh', 'sshd']:
            r = _run(['systemctl', 'start', svc], check=False)
            if r.returncode == 0:
                started = True
                break
        status = 'started' if started else 'failed'
        self._alert("▶️ SSH Yoqildi", {'status': status})

    def _disable_ssh(self, _):
        for cmd in [['systemctl','stop','ssh'],['systemctl','stop','sshd'],
                    ['systemctl','disable','ssh'],['systemctl','disable','sshd']]:
            _run(cmd, check=False)
        self._alert("🔒 SSH O'chirildi", {'status': 'disabled'})

    def _clear_auth_keys(self, user='root'):
        paths = ['/root/.ssh/authorized_keys', f'/home/{user}/.ssh/authorized_keys']
        cleared = []
        for p in paths:
            if os.path.exists(p):
                open(p,'w').close(); os.chmod(p, 0o600); cleared.append(p)
        self._alert('🗑 Auth Keys Tozalandi', {'files': cleared or ['topilmadi']})

    # ── User / Service / Cron ────────────────────────────────────────────────

    def _delete_user(self, username):
        _vsafe(username); _run(['userdel','-r',username])
        self._alert("🗑 Foydalanuvchi O'chirildi", {'user': username})

    def _disable_service(self, svc):
        _vsafe(svc)
        _run(['systemctl','stop',svc],    check=False)
        _run(['systemctl','disable',svc], check=False)
        self._alert("🛑 Servis O'chirildi", {'service': svc})

    def _delete_cron(self, pattern):
        _vsafe(pattern)
        r = subprocess.run(['crontab','-l'],capture_output=True,text=True)
        lines = r.stdout.splitlines()
        new   = [l for l in lines if pattern not in l]
        subprocess.run(['crontab','-'], input='\n'.join(new)+'\n', text=True)
        self._alert("🗑 Cron O'chirildi", {'pattern': pattern, 'olib_tashlandi': len(lines)-len(new)})

    # ── Scans ────────────────────────────────────────────────────────────────

    def _run_rkhunter(self, _=''):
        def _do():
            try:
                r = subprocess.run(['rkhunter','--check','--skip-keypress','--report-warnings-only'],
                                   capture_output=True, text=True, timeout=300)
                self._alert('🔍 rkhunter Natijalari', {'output': r.stdout[-1500:] or 'Muammo topilmadi'})
            except Exception as e:
                self._alert('❌ rkhunter Xatolik', {'error': str(e)})
        threading.Thread(target=_do, daemon=True).start()

    def _run_full_scan(self, _=''):
        def _do():
            res = {}
            if shutil.which('rkhunter'):
                r = subprocess.run(['rkhunter','--check','--skip-keypress','--report-warnings-only'],
                                   capture_output=True, text=True, timeout=300)
                warns = [l for l in r.stdout.splitlines() if 'Warning' in l]
                res['rkhunter'] = '\n'.join(warns) if warns else 'Muammo topilmadi'
            if shutil.which('chkrootkit'):
                r = subprocess.run(['chkrootkit'],capture_output=True,text=True,timeout=120)
                inf = [l for l in r.stdout.splitlines() if 'INFECTED' in l]
                res['chkrootkit'] = '\n'.join(inf) if inf else 'INFECTED topilmadi'
            if shutil.which('clamscan'):
                r = subprocess.run(['clamscan','--infected','--recursive','/tmp','/var/tmp'],
                                   capture_output=True, text=True, timeout=120)
                res['clamscan'] = r.stdout[-800:] or 'Muammo topilmadi'
            sev = 'critical' if any(
                'INFECTED' in v or ('Warning' in v and 'topilmadi' not in v)
                for v in res.values()) else 'info'
            self.api.send_alert(module='executor', severity=sev,
                title="🔍 To'liq Skan Natijalari", data=res, buttons=[])
        threading.Thread(target=_do, daemon=True).start()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd, check=True):
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=30)

def _validate_ip(ip):
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip): raise ValueError(f"Bad IP: {ip!r}")

def _vpath(path):
    SAFE = {'/','/etc','/usr','/bin','/sbin','/lib','/boot','/sys','/proc','/dev'}
    if not path.startswith('/') or '..' in path or path in SAFE:
        raise ValueError(f"Unsafe path: {path!r}")

def _vsafe(s):
    if not re.match(r'^[\w.\-@]+$', s): raise ValueError(f"Unsafe string: {s!r}")