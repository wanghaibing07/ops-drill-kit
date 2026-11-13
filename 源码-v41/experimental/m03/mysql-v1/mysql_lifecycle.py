#!/usr/bin/env python3
"""M03 isolated MySQL lifecycle candidate; no business DB access."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

BASE = Path('/run/opsdrill-m03-mysql')
HERE = Path(__file__).resolve().parent
RUN_ID = re.compile(r'^[0-9a-f]{24}$')
DB_ID = re.compile(r'^[0-9a-f]{16}$')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
ZERO_UUID = '00000000-0000-0000-0000-000000000000'
WORKER_LIMIT = 900
HOLDER_LIMIT = 480
START_WAIT = 600
RESET_WAIT = 180
DEPENDENCIES = {
    'm04_controller.py': '46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9',
    'm03_vm_probe.py': '0af53e4b3f18819699d4c68dc44f7a3cdc1ae4abe2696f2b661f92a4bfd53aac',
}
DIAG_STAGES = frozenset(('WORKER_IDENTITY', 'DEPENDENCIES', 'CONTROLLER_SETUP', 'DB_DIRECTORY',
    'CONTROLLER_LOCK', 'STATE_INIT', 'DB_START', 'PREPARE_LIMIT', 'PREPARE_LOGGING', 'PREPARE_AUDIT',
    'PREPARE_ACCOUNT_CHECK', 'PREPARE_MEMFD', 'PREPARE_INTENT', 'PREPARE_CREATE', 'PREPARE_GRANTS',
    'PREPARE_CONNECT', 'PREPARE_READY', 'CONTROL_SOCKET', 'SERVE', 'INJECT', 'CHECK', 'RESOLVE',
    'RESET', 'CLEANUP_HOLDERS', 'CLEANUP_IDENTITY', 'CLEANUP_ACCOUNT', 'CLEANUP_INSTANCES', 'CLEANUP_RECEIPT'))
DIAG_ERRORS = frozenset(('Refused', 'SafetyError', 'TimeoutError', 'TimeoutExpired', 'FileNotFoundError',
    'FileExistsError', 'PermissionError', 'OSError', 'ValueError', 'KeyError', 'TypeError',
    'RuntimeError', 'ImportError', 'AttributeError', 'JSONDecodeError', 'OtherError', 'UNKNOWN'))

class Refused(RuntimeError):
    pass

def require(ok, reason):
    if not ok:
        raise Refused(reason)

def secure_dir(path):
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700,
            'unsafe directory')

def secure_file(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600
            and st.st_nlink == 1, 'unsafe file')

def load(path):
    secure_file(path)
    with path.open(encoding='ascii') as stream:
        return json.load(stream)

def save(path, obj):
    tmp = path.parent / ('.tmp-' + secrets.token_hex(16))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii') as stream:
        json.dump(obj, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def save_once(path, obj):
    # Establish worker identity before creating DB resources; never replace it.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii') as stream:
        json.dump(obj, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def diagnostic_category(exc):
    category = type(exc).__name__
    return category if category in DIAG_ERRORS else 'OtherError'

class Diagnostic:
    """Best-effort, fixed-vocabulary diagnostics; never serialize an exception."""
    def __init__(self, path):
        self.path, self.stage, self.failed = path, 'WORKER_IDENTITY', False

    def advance(self, stage):
        if self.failed:
            return
        if stage not in DIAG_STAGES:
            raise ValueError('invalid diagnostic stage')
        self.stage = stage
        self._write('UNKNOWN')

    def fail(self, exc):
        if not self.failed:
            self.failed = True
            self._write(diagnostic_category(exc))

    def _write(self, category):
        try:
            save(self.path / 'diagnostic.json', {'stage': self.stage, 'error': category})
        except Exception:
            # Diagnostics are never a prerequisite for verified cleanup.
            pass

def read_diagnostic(path):
    try:
        value = load(path / 'diagnostic.json')
        if (isinstance(value, dict) and set(value) == {'stage', 'error'}
                and value['stage'] in DIAG_STAGES and value['error'] in DIAG_ERRORS):
            return value
    except (OSError, ValueError, TypeError, Refused):
        pass
    return None

def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip().lower()

def proc_start(pid):
    data = Path('/proc/%d/stat' % pid).read_text(encoding='ascii')
    return int(data[data.rfind(')') + 2:].split()[19])

def run_directory(rid):
    require(bool(RUN_ID.fullmatch(rid)), 'bad run id')
    secure_dir(BASE)
    path = BASE / rid
    secure_dir(path)
    return path

def owner_for(path, rid):
    owner = load(path / 'owner.json')
    require(owner.get('version') == 1 and owner.get('run_id') == rid
            and DB_ID.fullmatch(owner.get('db_id', '')) is not None
            and re.fullmatch(r'[0-9a-f]{64}', owner.get('token', '')) is not None,
            'invalid owner')
    return owner

def load_dependencies():
    modules = []
    for filename, expected in DEPENDENCIES.items():
        path = HERE / filename
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
                and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                'dependency integrity mismatch')
        spec = importlib.util.spec_from_file_location('_m03_dep_' + filename[:-3], path)
        require(spec is not None and spec.loader is not None, 'dependency unavailable')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    return modules

def identity(path, owner):
    obj = load(path / 'identity.json')
    pid = obj.get('pid')
    require(obj.get('run_id') == owner['run_id'] and obj.get('boot_id') == owner['boot_id']
            and type(pid) is int and pid > 1 and type(obj.get('start')) is int, 'invalid identity')
    return obj

def live_pid(path, owner):
    obj = identity(path, owner)
    require(owner['boot_id'] == boot_id() and proc_start(obj['pid']) == obj['start'], 'worker not owned')
    return obj['pid']

def control(path, owner, action):
    pid = live_pid(path, owner)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3 if action == 'status' else 180)
        s.connect(str(path / 'control.sock'))
        peer, uid, _ = struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer == pid and uid == 0, 'peer mismatch')
        s.sendall(json.dumps({'token': owner['token'], 'action': action}).encode('ascii') + b'\n')
        raw = bytearray()
        while len(raw) <= 8192:
            part = s.recv(4096)
            if not part:
                break
            raw.extend(part)
    require(len(raw) <= 8192, 'oversized response')
    obj = json.loads(raw)
    require(obj.get('run_id') == owner['run_id'] and obj.get('pid') == pid and obj.get('ok') is True,
            'request not confirmed')
    return obj

def receipt_ok(path, owner):
    try:
        return load(path / 'receipt.json') == {'run_id': owner['run_id'], 'db_id': owner['db_id'],
            'boot_id': owner['boot_id'], 'owner_hash': hashlib.sha256(owner['token'].encode()).hexdigest(),
            'status': 'STOPPED'}
    except (OSError, ValueError, Refused):
        return False

def write_receipt(path, owner):
    save(path / 'receipt.json', {'run_id': owner['run_id'], 'db_id': owner['db_id'],
        'boot_id': owner['boot_id'], 'owner_hash': hashlib.sha256(owner['token'].encode()).hexdigest(),
        'status': 'STOPPED'})

def acquire_lock(ctl, directory):
    fd = os.open(directory / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077,
                'unsafe controller lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise

def state_belongs(state, owner):
    require(state.get('version') == 1 and state.get('run_id') == owner['db_id']
            and state.get('business_phase') == 'M03_TEST_ONLY'
            and state.get('primary_uuid') == ZERO_UUID and state.get('replay_account') is None
            and state.get('boot_id') == owner['boot_id'], 'database owner mismatch')

def mysql_sql_stdin(ctl, p, rid, state, statement):
    p.target(ctl, rid, state)
    sock = ctl.paths(rid, 'target')[2]
    args = ['/usr/bin/mysql', '--no-defaults', '--protocol=SOCKET', '--socket=' + str(sock),
            '--user=root', '--batch', '--skip-column-names']
    result = subprocess.run(args, input=statement.encode('ascii'), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=15, env=ENV, check=False)
    require(result.returncode == 0, 'isolated admin command failed')

def option_fd(password):
    fd = os.memfd_create('m03-synthetic', os.MFD_CLOEXEC)
    try:
        os.fchmod(fd, 0o600)
        data = ('[client]\npassword=' + password + '\n').encode('ascii')
        while data:
            written = os.write(fd, data)
            require(written > 0, 'memfd write failed')
            data = data[written:]
        return fd
    except BaseException:
        os.close(fd)
        raise

def cleanup_account(ctl, probe, rid, state):
    record = state.get('m03_probe')
    if record is None:
        return
    require(isinstance(record, dict) and record.get('account') == 'm03_' + rid,
            'invalid account ownership')
    probe.target(ctl, rid, state)
    name = 'm03_' + rid
    probe.query(ctl, rid, state, "DROP USER IF EXISTS '" + name + "'@'localhost'")
    remaining = probe.query(ctl, rid, state, "SELECT COUNT(*) FROM mysql.user WHERE User='" + name +
                            "' AND Host='localhost'")
    require(remaining == '0', 'account cleanup unconfirmed')
    state['m03_probe']['phase'] = 'ACCOUNT_REMOVED'

def verify_plugin_inventory(raw):
    """Permit only known built-in audit helpers; reject every dynamic plugin."""
    require(isinstance(raw, str) and bool(raw), 'plugin inventory missing')
    seen = set()
    allowed = {'sha2_cache_cleaner', 'mysqlx_cache_cleaner'}
    statuses = {'ACTIVE', 'INACTIVE', 'DISABLED', 'DELETED'}
    for line in raw.splitlines():
        fields = line.split('\t')
        require(len(fields) == 4, 'invalid plugin inventory')
        name, kind, status, origin = fields
        require(re.fullmatch(r'[A-Za-z0-9_]{1,128}', name) is not None
                and re.fullmatch(r'[A-Z][A-Z0-9_ -]{0,63}', kind) is not None
                and status in statuses and origin in ('BUILTIN', 'DYNAMIC')
                and name not in seen, 'invalid plugin inventory')
        seen.add(name)
        require(origin == 'BUILTIN', 'dynamic plugin present')
        if status == 'ACTIVE' and (kind == 'AUDIT' or 'audit' in name.lower() or name in allowed):
            require(name in allowed and kind == 'AUDIT', 'unapproved audit plugin')

class MySQLDrill:
    def __init__(self, ctl, probe, rid, directory, state, diagnostic=None):
        self.ctl, self.p, self.rid, self.directory, self.state = ctl, probe, rid, directory, state
        self.name = 'm03_' + rid
        require(re.fullmatch(r'm03_[0-9a-f]{16}', self.name) is not None, 'invalid account')
        self.phase = 'STARTING'
        self.holders = []
        self.spawn_ambiguous = False
        self.fd = None
        self.count = None
        self.diagnostic = diagnostic

    def progress(self, stage):
        if self.diagnostic is not None:
            self.diagnostic.advance(stage)

    def query(self, sql):
        return self.p.query(self.ctl, self.rid, self.state, sql)

    def prepare(self):
        self.progress('PREPARE_LIMIT')
        self.count = self.p.bounded_limit(self.query('SELECT @@global.max_connections'))
        # No business secrets are used. Refuse unexpected plugin code and
        # unapproved audit hooks before creating even the public marker account.
        self.progress('PREPARE_LOGGING')
        flags = self.query('SELECT @@global.general_log,@@global.log_bin')
        require(flags == '0\t0', 'target logging enabled')
        self.progress('PREPARE_AUDIT')
        plugins = self.query("SELECT PLUGIN_NAME,PLUGIN_TYPE,PLUGIN_STATUS,"
                             "IF(PLUGIN_LIBRARY IS NULL,'BUILTIN','DYNAMIC') FROM information_schema.plugins")
        verify_plugin_inventory(plugins)
        self.progress('PREPARE_ACCOUNT_CHECK')
        exists = "SELECT COUNT(*) FROM mysql.user WHERE User='" + self.name + "' AND Host='localhost'"
        require(self.query(exists) == '0', 'account exists')
        # The disposable account uses the existing probe's public marker. It is
        # deliberately not a secret; the socket and dedicated data are isolated.
        self.progress('PREPARE_MEMFD')
        password = self.p.MARKER
        require(isinstance(password, str) and re.fullmatch(r'[A-Za-z0-9_]{16,64}', password),
                'invalid synthetic marker')
        self.fd = option_fd(password)
        self.progress('PREPARE_INTENT')
        self.state['m03_probe'] = {'phase': 'CREATE_ATTEMPTED', 'account': self.name,
                                   'limit': self.count, 'holders_state': 'NONE'}
        self.ctl.save(self.directory, self.state)
        self.progress('PREPARE_CREATE')
        mysql_sql_stdin(self.ctl, self.p, self.rid, self.state,
                        "CREATE USER '" + self.name + "'@'localhost' IDENTIFIED BY '" + password + "'")
        password = None
        self.progress('PREPARE_GRANTS')
        grants = self.query("SHOW GRANTS FOR '" + self.name + "'@'localhost'").splitlines()
        require(grants == ['GRANT USAGE ON *.* TO `' + self.name + '`@`localhost`'], 'unexpected grants')
        self.progress('PREPARE_CONNECT')
        result = self.p.one_client(self.ctl, self.rid, self.name, self.fd)
        require(result.returncode == 0 and result.stdout.strip() == b'1', 'initial connection failed')
        self.progress('PREPARE_READY')
        self.phase = 'READY'
        self.state['m03_probe']['phase'] = 'READY'
        self.ctl.save(self.directory, self.state)

    def inject(self):
        require(self.phase == 'READY', 'not ready to inject')
        self.phase = 'UNCERTAIN'
        self.state['m03_probe']['phase'] = 'INJECTING'
        self.state['m03_probe']['holders_state'] = 'MAY_EXIST'
        self.ctl.save(self.directory, self.state)
        for _ in range(self.count):
            self.p.target(self.ctl, self.rid, self.state)
            with self.p.client_option_fd(self.fd) as fd:
                args = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=5s', str(HOLDER_LIMIT)] + \
                       self.p.client_args(self.ctl, self.rid, self.name, fd)
                self.spawn_ambiguous = True
                self.holders.append(subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=ENV, pass_fds=(fd,), start_new_session=True))
                self.spawn_ambiguous = False
        self.p.wait_sleepers(self.ctl, self.rid, self.state, self.name, self.count)
        require(self.p.is_1040(self.p.one_client(self.ctl, self.rid, self.name, self.fd)), '1040 not observed')
        self.phase = 'FAULT'
        self.state['m03_probe']['phase'] = 'FAULT'
        self.ctl.save(self.directory, self.state)

    def check(self):
        require(self.phase in ('READY', 'FAULT', 'RELEASED'), 'phase unknown')
        self.p.target(self.ctl, self.rid, self.state)
        n = self.p.sleepers(self.ctl, self.rid, self.state, self.name)
        result = self.p.one_client(self.ctl, self.rid, self.name, self.fd)
        n_after = self.p.sleepers(self.ctl, self.rid, self.state, self.name)
        require(n == n_after, 'connection count changed')
        if self.phase == 'FAULT':
            require(n == self.count and self.p.is_1040(result)
                    and all(holder.poll() is None for holder in self.holders), 'fault unconfirmed')
            return {'status': 'FAULT', 'sleep_connections': n, 'mysql_error': 1040}
        require(n == 0 and result.returncode == 0 and result.stdout.strip() == b'1', 'recovery unconfirmed')
        return {'status': 'READY' if self.phase == 'READY' else 'RECOVERED',
                'sleep_connections': n, 'connection': 'OK'}

    def resolve(self):
        require(self.phase == 'FAULT', 'not in fault phase')
        self.phase = 'UNCERTAIN'
        self.state['m03_probe']['phase'] = 'RELEASING'
        self.ctl.save(self.directory, self.state)
        self.p.stop_holders(self.holders)
        self.state['m03_probe']['holders_state'] = 'CLOSED'
        self.ctl.save(self.directory, self.state)
        self.p.wait_sleepers(self.ctl, self.rid, self.state, self.name, 0)
        result = self.p.one_client(self.ctl, self.rid, self.name, self.fd)
        require(result.returncode == 0 and result.stdout.strip() == b'1', 'connection did not recover')
        self.phase = 'RELEASED'
        self.state['m03_probe']['phase'] = 'RELEASED'
        self.ctl.save(self.directory, self.state)

    def close_holders(self):
        try:
            self.p.stop_holders(self.holders)
            require(not self.spawn_ambiguous, 'holder launch unconfirmed')
            record = self.state.get('m03_probe')
            if record is not None:
                record['holders_state'] = 'CLOSED'
                self.ctl.save(self.directory, self.state)
        finally:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None

def start(rid):
    require(bool(RUN_ID.fullmatch(rid)), 'invalid run id')
    BASE.mkdir(mode=0o700, exist_ok=True)
    secure_dir(BASE)
    path = BASE / rid
    path.mkdir(mode=0o700)
    owner = {'version': 1, 'run_id': rid, 'db_id': secrets.token_hex(8),
             'boot_id': boot_id(), 'token': secrets.token_hex(32)}
    save(path / 'owner.json', owner)
    process = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()), '_worker', rid],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True, start_new_session=True, env=ENV)
    deadline = time.monotonic() + START_WAIT
    while time.monotonic() < deadline:
        require(process.poll() is None, 'worker exited before ready')
        try:
            response = control(path, owner, 'status')
            require(response.get('phase') == 'READY', 'worker not ready')
            return {'run_id': rid, 'status': 'READY', 'db_scope': 'isolated_socket_only'}
        except (OSError, ValueError, KeyError, Refused):
            time.sleep(.3)
    raise Refused('start unconfirmed; retain run id')

def recover_stopped_worker(path, owner, ctl):
    require(owner['boot_id'] == boot_id(), 'different boot')
    obj = identity(path, owner)
    try:
        current = proc_start(obj['pid'])
    except FileNotFoundError:
        current = None
    require(current != obj['start'], 'worker may be alive')
    ctl.setup()
    directory = ctl.BASE / owner['db_id']
    ctl.secure_dir(directory)
    lock = acquire_lock(ctl, directory)
    try:
        state = ctl.load(directory, owner['db_id'])
        state_belongs(state, owner)
        ctl.require_same_boot(state)
        record = state.get('m03_probe')
        holders_ok = record is None or (isinstance(record, dict) and
                                        record.get('holders_state') in ('NONE', 'CLOSED'))
        account_ok = True
        try:
            _, probe = load_dependencies()
            cleanup_account(ctl, probe, owner['db_id'], state)
        except Exception:
            account_ok = False
        ctl.reset(owner['db_id'], directory, state)
        require(account_ok, 'account cleanup unconfirmed')
        require(holders_ok, 'holder cleanup unconfirmed')
        require(state.get('phase') == 'STOPPED', 'reset not confirmed')
        write_receipt(path, owner)
    finally:
        os.close(lock)

def operation(rid, action):
    path = run_directory(rid)
    owner = owner_for(path, rid)
    if action == 'reset' and receipt_ok(path, owner):
        return {'run_id': rid, 'status': 'STOPPED'}
    require(owner['boot_id'] == boot_id(), 'different boot')
    if action == 'reset':
        try:
            control(path, owner, 'reset')
        except (OSError, ValueError, Refused):
            ctl, _ = load_dependencies()
            recover_stopped_worker(path, owner, ctl)
        deadline = time.monotonic() + RESET_WAIT
        while time.monotonic() < deadline:
            if receipt_ok(path, owner):
                return {'run_id': rid, 'status': 'STOPPED'}
            time.sleep(.1)
        raise Refused('reset not confirmed')
    result = control(path, owner, action)
    return {k: v for k, v in result.items() if k not in ('pid', 'ok', 'phase')}

def worker(rid):
    path = run_directory(rid)
    owner = owner_for(path, rid)
    diagnostic = Diagnostic(path)
    diagnostic.advance('WORKER_IDENTITY')
    try:
        require(owner['boot_id'] == boot_id(), 'different boot')
        _worker(rid, path, owner, diagnostic)
    except BaseException as exc:
        diagnostic.fail(exc)
        raise

def _worker(rid, path, owner, diagnostic):
    save_once(path / 'identity.json', {'run_id': rid, 'boot_id': owner['boot_id'],
                                       'pid': os.getpid(), 'start': proc_start(os.getpid())})
    diagnostic.advance('DEPENDENCIES')
    ctl, probe = load_dependencies()
    diagnostic.advance('CONTROLLER_SETUP')
    ctl.setup()
    diagnostic.advance('DB_DIRECTORY')
    directory = ctl.BASE / owner['db_id']
    directory.mkdir(mode=0o700)
    diagnostic.advance('CONTROLLER_LOCK')
    lock = acquire_lock(ctl, directory)
    state = None
    drill = None
    server = None
    deadline_fired = False
    def expired(_signum, _frame):
        nonlocal deadline_fired
        deadline_fired = True
        raise TimeoutError('worker deadline')
    old = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, WORKER_LIMIT)
    try:
        diagnostic.advance('STATE_INIT')
        boot, now = ctl.boot_context()
        require(boot == owner['boot_id'], 'boot changed')
        state = {'version': 1, 'run_id': owner['db_id'], 'phase': 'PREPARING',
                 'primary_uuid': ZERO_UUID, 'uuids': {}, 'attempted': [], 'boot_id': boot,
                 'deadline_boottime': now + WORKER_LIMIT, 'business_phase': 'M03_TEST_ONLY'}
        ctl.save(directory, state)
        diagnostic.advance('DB_START')
        ctl.start(owner['db_id'], directory, state)
        state_belongs(state, owner)
        drill = MySQLDrill(ctl, probe, owner['db_id'], directory, state, diagnostic)
        drill.prepare()
        diagnostic.advance('CONTROL_SOCKET')
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path / 'control.sock'))
        os.chmod(path / 'control.sock', 0o600)
        server.listen(8)
        server.settimeout(1)
        running = True
        diagnostic.advance('SERVE')
        while running:
            try:
                conn, _ = server.accept()
            except socket.timeout:
                if deadline_fired:
                    raise
                continue
            with conn:
                conn.settimeout(1)
                try:
                    req = json.loads(conn.recv(4096))
                    require(isinstance(req, dict) and isinstance(req.get('token'), str)
                            and secrets.compare_digest(req['token'], owner['token']), 'unauthorized')
                    action = req.get('action')
                    result = {'ok': True, 'run_id': rid, 'pid': os.getpid()}
                    if action == 'status':
                        result['phase'] = drill.phase
                    elif action == 'inject':
                        diagnostic.advance('INJECT')
                        drill.inject()
                        result['status'] = 'INJECTED'
                    elif action == 'check':
                        diagnostic.advance('CHECK')
                        result.update(drill.check())
                    elif action == 'resolve':
                        diagnostic.advance('RESOLVE')
                        drill.resolve()
                        result['status'] = 'RELEASED'
                    elif action == 'reset':
                        diagnostic.advance('RESET')
                        running = False
                        result['status'] = 'STOPPING'
                    else:
                        raise Refused('unknown action')
                    conn.sendall(json.dumps(result).encode('ascii'))
                except TimeoutError:
                    if deadline_fired:
                        raise
                except Exception as exc:
                    diagnostic.fail(exc)
                    # Never return SQL, diagnostics, credentials, or subprocess output.
                    try:
                        conn.sendall(b'{"ok":false}')
                    except OSError:
                        pass
    except BaseException as exc:
        diagnostic.fail(exc)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
        if server is not None:
            server.close()
        errors = False
        if drill is not None:
            try:
                diagnostic.advance('CLEANUP_HOLDERS')
                drill.close_holders()
            except Exception as exc:
                diagnostic.fail(exc)
                errors = True
        if state is not None:
            try:
                diagnostic.advance('CLEANUP_IDENTITY')
                state_belongs(state, owner)
            except Exception as exc:
                diagnostic.fail(exc)
                errors = True
            else:
                try:
                    diagnostic.advance('CLEANUP_ACCOUNT')
                    cleanup_account(ctl, probe, owner['db_id'], state)
                except Exception as exc:
                    diagnostic.fail(exc)
                    errors = True
                try:
                    diagnostic.advance('CLEANUP_INSTANCES')
                    ctl.reset(owner['db_id'], directory, state)
                    require(state.get('phase') == 'STOPPED', 'reset not confirmed')
                except Exception as exc:
                    diagnostic.fail(exc)
                    errors = True
        else:
            errors = True
        if not errors:
            diagnostic.advance('CLEANUP_RECEIPT')
            write_receipt(path, owner)
        os.close(lock)

def main():
    parser = argparse.ArgumentParser(description='M03 isolated MySQL lifecycle candidate')
    parser.add_argument('action', choices=['start', 'inject', 'check', 'resolve', 'reset', '_worker'])
    parser.add_argument('run_id')
    args = parser.parse_args()
    try:
        require(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root required')
        if args.action == '_worker':
            worker(args.run_id)
            return 0
        result = start(args.run_id) if args.action == 'start' else operation(args.run_id, args.action)
        print(json.dumps(result, sort_keys=True))
        return 1 if result.get('status') == 'FAULT' else 0
    except Exception as exc:
        result = {'status': 'UNCONFIRMED', 'error_type': diagnostic_category(exc)}
        if args.action != '_worker':
            try:
                path = run_directory(args.run_id)
                owner_for(path, args.run_id)
                diagnostic = read_diagnostic(path)
                if diagnostic is not None:
                    result['diagnostic'] = diagnostic
            except (OSError, ValueError, TypeError, Refused):
                pass
        print(json.dumps(result, sort_keys=True), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
