#!/usr/bin/env python3
"""Guarded N03 502/504 drills with independent recovery protections."""
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path('/run/opsdrill-n03')
GATE_DIR = pathlib.Path('/run/opsdrill-n03-gate')
GATE_NAME = 'slow.trigger'
STATE = 'current.json'
LOCK = '.controller.lock'
CODE = pathlib.Path(__file__).resolve()
BOOT_ID = pathlib.Path('/proc/sys/kernel/random/boot_id')
SERVICE = 'orderguard-api.service'
WATCHDOG_SECONDS = 120
WATCHDOG_SCHEDULE = '2min'
GATE_TTL_SECONDS = 120
RID = re.compile(r'^[0-9a-f]{24}$')
SHA = re.compile(r'^[0-9a-f]{64}$')
OWNER = re.compile(r'^[0-9a-f]{32}$')
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Refused(Exception):
    pass


def require(ok, message):
    if not ok: raise Refused(message)


def guard():
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    p = subprocess.run(['systemd-detect-virt', '--vm'], capture_output=True, text=True, timeout=5)
    require(p.returncode == 0 and p.stdout.strip() == 'vmware', 'NOT_VMWARE')
    marker = pathlib.Path('/etc/opsdrill-lab')
    st = marker.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
            not st.st_mode & 0o022 and marker.read_bytes().strip() == b'ops-drill-kit', 'BAD_LAB_MARKER')


def directory():
    try: os.mkdir(ROOT, 0o700)
    except FileExistsError: pass
    st = ROOT.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700, 'UNSAFE_STATE_DIR')
    return os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


@contextlib.contextmanager
def locked():
    dfd = directory()
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) == 0o600, 'UNSAFE_LOCK')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield dfd
    finally:
        os.close(fd)
        os.close(dfd)


def write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        require(n > 0, 'WRITE_FAILED')
        view = view[n:]


def gate_directory(create=False):
    created = False
    if create:
        old_umask = os.umask(0o022)
        try:
            try:
                os.mkdir(GATE_DIR, 0o755)
                created = True
            except FileExistsError:
                pass
        finally:
            os.umask(old_umask)
    try:
        fd = os.open(GATE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if not create: return None
        raise
    try:
        if created: os.fchmod(fd, 0o755)
        st = os.fstat(fd)
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o755,
                'UNSAFE_GATE_DIR')
        return fd
    except Exception:
        os.close(fd)
        raise


def gate_payload(state):
    rid = state.get('run_id')
    require(isinstance(rid, str) and RID.fullmatch(rid), 'BAD_RUN_ID')
    boot = state.get('boot_id')
    created, expires = state.get('gate_created_ns'), state.get('gate_expires_ns')
    require(isinstance(boot, str) and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', boot),
            'BAD_GATE_BOOT_ID')
    require(type(created) is int and type(expires) is int and created >= 0 and
            0 < expires - created <= GATE_TTL_SECONDS * 1_000_000_000, 'BAD_GATE_TTL')
    return ('opsdrill-n03-504:%s:%s:%d:%d\n' % (rid, boot, created, expires)).encode('ascii')


def gate_live(state):
    gate_payload(state)
    now = time.monotonic_ns()
    return state['gate_created_ns'] <= now < state['gate_expires_ns']


def gate_entry(dfd, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o644 and
                st.st_nlink in (1, 2) and st.st_size <= 160, 'UNSAFE_GATE')
        data = os.read(fd, 161)
        require(len(data) == st.st_size, 'GATE_CHANGED')
        return st, data
    finally:
        os.close(fd)


def gate_present(state=None):
    dfd = gate_directory()
    if dfd is None: return False
    try:
        names = set(os.listdir(dfd))
        if state is None:
            require(not names, 'UNOWNED_GATE')
            return False
        require(names <= {GATE_NAME}, 'GATE_INCOMPLETE_OR_FOREIGN')
        entry = gate_entry(dfd, GATE_NAME)
        if entry is None: return False
        st, data = entry
        require(st.st_nlink == 1 and data == gate_payload(state), 'GATE_OWNER_MISMATCH')
        return True
    finally:
        os.close(dfd)


def create_gate(state):
    data = gate_payload(state)
    rid = state['run_id']
    require(gate_live(state), 'GATE_EXPIRED_BEFORE_INJECT')
    temporary = '.new-' + rid
    dfd = gate_directory(create=True)
    try:
        require(not os.listdir(dfd), 'UNOWNED_GATE')
        old_umask = os.umask(0o022)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dfd)
        finally:
            os.umask(old_umask)
        try:
            os.fchmod(fd, 0o644)
            write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(temporary, GATE_NAME, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        os.fsync(dfd)
        os.unlink(temporary, dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def remove_gate(state):
    data = gate_payload(state)
    rid = state['run_id']
    temporary = '.new-' + rid
    dfd = gate_directory()
    if dfd is None: return False
    try:
        names = set(os.listdir(dfd))
        require(names <= {GATE_NAME, temporary}, 'UNOWNED_GATE')
        trigger = gate_entry(dfd, GATE_NAME)
        temp = gate_entry(dfd, temporary)
        if trigger is not None:
            st, content = trigger
            require(content == data, 'GATE_OWNER_MISMATCH')
            if st.st_nlink == 2:
                require(temp is not None and (temp[0].st_dev, temp[0].st_ino) == (st.st_dev, st.st_ino)
                        and temp[1] == data, 'GATE_LINK_MISMATCH')
            else:
                require(st.st_nlink == 1, 'GATE_LINK_MISMATCH')
        if temp is not None:
            st, content = temp
            require(data.startswith(content), 'GATE_OWNER_MISMATCH')
            if st.st_nlink == 2:
                require(trigger is not None and (trigger[0].st_dev, trigger[0].st_ino) == (st.st_dev, st.st_ino),
                        'GATE_LINK_MISMATCH')
            else:
                require(st.st_nlink == 1, 'GATE_LINK_MISMATCH')
        for name, entry in ((GATE_NAME, trigger), (temporary, temp)):
            if entry is not None:
                current = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                require((current.st_dev, current.st_ino) == (entry[0].st_dev, entry[0].st_ino), 'GATE_CHANGED')
                os.unlink(name, dir_fd=dfd)
        if trigger is not None or temp is not None: os.fsync(dfd)
        return trigger is not None or temp is not None
    finally:
        os.close(dfd)


def write_state(dfd, state):
    temp = '.new-' + secrets.token_hex(8)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        write_all(fd, (json.dumps(state, sort_keys=True) + '\n').encode())
        os.fsync(fd)
    finally: os.close(fd)
    os.replace(temp, STATE, src_dir_fd=dfd, dst_dir_fd=dfd)
    os.fsync(dfd)


def read_state(dfd):
    try: fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError: return None
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= 8192, 'UNSAFE_STATE')
        obj = json.loads(os.read(fd, 8193))
    finally: os.close(fd)
    require(isinstance(obj, dict) and obj.get('version') == 1 and obj.get('kind') in ('n03-502', 'n03-504'), 'BAD_STATE')
    rid = obj.get('run_id')
    require(isinstance(rid, str) and RID.fullmatch(rid), 'BAD_RUN_ID')
    allowed = ('PREPARING', 'STOP_REQUESTED', 'FAULT', 'WATCHDOG_HEALTHY') if obj['kind'] == 'n03-502' else \
              ('PREPARING', 'GATE_REQUESTED', 'FAULT', 'WATCHDOG_HEALTHY')
    require(obj.get('phase') in allowed, 'BAD_PHASE')
    for key in ('helper_sha', 'service_sha'):
        require(isinstance(obj.get(key), str) and SHA.fullmatch(obj[key]), 'BAD_STATE_HASH')
    require(obj.get('boot_id') == BOOT_ID.read_text(encoding='ascii').strip(), 'BOOT_CHANGED')
    # Old unowned v1 state stays valid; partial or unknown bindings never do.
    ownership = (obj.get('owner_kind'), obj.get('owner_id'))
    require(ownership == (None, None) and 'owner_kind' not in obj and 'owner_id' not in obj or
            ownership[0] == 'C01_APP_DOWN_V1' and isinstance(ownership[1], str) and
            OWNER.fullmatch(ownership[1]) and obj['kind'] == 'n03-502', 'BAD_OWNERSHIP')
    if obj['kind'] == 'n03-504':
        gate_payload(obj)
    require(obj.get('timer') == 'opsdrill-n03-recover-' + rid + '.timer', 'BAD_TIMER')
    require(obj.get('helper') == 'helper-' + obj['helper_sha'] + '.py', 'BAD_HELPER')
    require(isinstance(obj.get('original_pid'), int) and obj['original_pid'] > 0 and
            isinstance(obj.get('original_invocation'), str) and re.fullmatch(r'[0-9a-f]{32}', obj['original_invocation']),
            'BAD_ORIGINAL_SERVICE')
    return obj


def helper_path(state):
    return ROOT / state['helper']


def read_secure(path, max_size=131072):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= max_size, 'UNSAFE_FILE')
        return os.read(fd, max_size + 1), st
    finally: os.close(fd)


def install_helper(dfd):
    # The candidate program is read once, then pinned in a root-only directory.
    fd = os.open(CODE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and not st.st_mode & 0o022 and st.st_size <= 131072,
                'UNSAFE_CONTROLLER')
        data = os.read(fd, 131073)
        require(len(data) <= 131072, 'UNSAFE_CONTROLLER')
    finally: os.close(fd)
    digest = hashlib.sha256(data).hexdigest()
    name = 'helper-' + digest + '.py'
    try:
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    except FileExistsError:
        existing, meta = read_secure(ROOT / name)
        require(stat.S_IMODE(meta.st_mode) == 0o600 and existing == data, 'HELPER_CHANGED')
    else:
        try:
            write_all(out, data)
            os.fsync(out)
        finally: os.close(out)
        os.fsync(dfd)
    return name, digest


def run(*args, timeout=15):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
    require(p.returncode == 0, 'COMMAND_FAILED_' + pathlib.Path(args[0]).name)
    return p.stdout


def props(unit, names):
    out = run('/usr/bin/systemctl', 'show', unit, '--no-pager', '--property=' + ','.join(names))
    values = {}
    for line in out.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            require(key not in values, 'DUPLICATE_PROPERTY')
            values[key] = value
    return values


def parse_argv(raw):
    path = re.search(r'(?:^|[;{]\s*)path=([^ ;]+)\s*;', raw)
    argv = re.search(r'(?:^|[;{]\s*)argv\[\]=(.*?)\s*;\s*ignore_errors=', raw)
    require(path is not None and argv is not None, 'UNIT_EXEC_FORMAT')
    text = argv.group(1).strip()
    require(not any(c in text for c in '\\"\''), 'UNIT_EXEC_ENCODING')
    return path.group(1), text.split()


def service_identity():
    names = ('LoadState', 'FragmentPath', 'DropInPaths', 'ExecStart', 'User', 'Group', 'Type',
             'UnitFileState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID')
    p = props(SERVICE, names)
    path, argv = parse_argv(p.get('ExecStart', ''))
    expected = ['/opt/ops-drill-kit/.venv/bin/python', '-m', 'uvicorn', 'app.main:app',
                '--host', '127.0.0.1', '--port', '8000']
    require(p.get('LoadState') == 'loaded' and p.get('FragmentPath') == '/etc/systemd/system/orderguard-api.service'
            and p.get('User') == 'devops' and p.get('Group') == 'devops' and p.get('Type') == 'exec'
            and p.get('UnitFileState') == 'enabled' and path == expected[0] and argv == expected, 'SERVICE_IDENTITY')
    files = [pathlib.Path(p['FragmentPath'])]
    for item in shlex.split(p.get('DropInPaths', '')):
        file = pathlib.Path(item)
        require(file.parent == pathlib.Path('/etc/systemd/system/orderguard-api.service.d') and
                re.fullmatch(r'[A-Za-z0-9_.-]+\.conf', file.name), 'UNSAFE_DROPIN')
        files.append(file)
    require(len(files) == len(set(files)), 'DUPLICATE_DROPIN')
    digest = hashlib.sha256()
    for file in sorted(files, key=str):
        content, st = read_secure(file, max_size=65536)
        require(len(content) == st.st_size, 'SERVICE_CONFIG_CHANGED')
        digest.update(str(file).encode() + b'\x00' + hashlib.sha256(content).digest())
    digest.update(json.dumps(expected).encode())
    return p, digest.hexdigest()


def request(port, path, timeout=4):
    try:
        with opener.open('http://127.0.0.1:%d%s' % (port, path), timeout=timeout) as response:
            return response.status, response.headers.get('X-Request-ID')
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get('X-Request-ID')


def ready():
    try:
        return request(8000, '/health')[0] == 200 and request(8080, '/health')[0] == 200 and request(8080, '/ready')[0] == 200
    except (OSError, urllib.error.URLError):
        return False


def wait_ready():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if ready(): return
        time.sleep(0.25)
    raise Refused('API_NOT_READY')


def helper_verified(state):
    data, st = read_secure(helper_path(state))
    require(stat.S_IMODE(st.st_mode) == 0o600 and hashlib.sha256(data).hexdigest() == state['helper_sha'], 'HELPER_CHANGED')


def timer_properties(state):
    return props(state['timer'], ('LoadState', 'ActiveState', 'FragmentPath', 'Unit', 'TimersMonotonic', 'NextElapseUSecMonotonic'))


def watchdog_argv(state):
    args = ['/usr/bin/python3', str(helper_path(state)), 'watchdog', state['run_id']]
    if 'owner_kind' in state:
        args.append(state['owner_id'])
    return args


def verify_watchdog_service(state, p):
    if p.get('LoadState') == 'not-found': return False
    unit = state['timer'][:-6] + '.service'
    path, argv = parse_argv(p.get('ExecStart', ''))
    require(p.get('FragmentPath') == '/run/systemd/transient/' + unit and p.get('Type') == 'exec' and
            p.get('User', '') in ('', 'root') and path == '/usr/bin/python3' and
            argv == watchdog_argv(state), 'WATCHDOG_IDENTITY')
    return True


def verify_timer(state, p):
    if p.get('LoadState') == 'not-found': return False
    require(p.get('FragmentPath') == '/run/systemd/transient/' + state['timer'] and
            p.get('Unit') == state['timer'][:-6] + '.service', 'TIMER_IDENTITY')
    return True


def watchdog_service_properties(state):
    return props(state['timer'][:-6] + '.service', ('LoadState', 'ActiveState', 'FragmentPath', 'Type', 'User', 'ExecStart', 'ControlGroup'))


def arm_watchdog(state):
    helper_verified(state)
    run('/usr/bin/systemd-run', '--unit=' + state['timer'][:-6], '--on-active=' + str(WATCHDOG_SECONDS) + 's',
        '--timer-property=AccuracySec=1s', '--service-type=exec', '--property=RuntimeMaxSec=30s',
        *watchdog_argv(state))
    require_watchdog_armed(state)


def require_watchdog_armed(state):
    helper_verified(state)
    timer = timer_properties(state)
    service = watchdog_service_properties(state)
    require(verify_timer(state, timer) and timer.get('ActiveState') == 'active' and
            ('OnActiveUSec=' + WATCHDOG_SCHEDULE + ' ;') in timer.get('TimersMonotonic', '') and
            timer.get('NextElapseUSecMonotonic') not in ('', 'n/a', None) and
            verify_watchdog_service(state, service), 'WATCHDOG_NOT_ARMED')


def cancel_watchdog(state):
    timer = timer_properties(state)
    if verify_timer(state, timer):
        service = watchdog_service_properties(state)
        verify_watchdog_service(state, service)
        if timer.get('ActiveState') == 'active':
            run('/usr/bin/systemctl', 'stop', state['timer'])
    timer = timer_properties(state)
    require(not (verify_timer(state, timer) and timer.get('ActiveState') == 'active'), 'TIMER_STILL_ACTIVE')
    service = watchdog_service_properties(state)
    exists = verify_watchdog_service(state, service)
    require(not (exists and service.get('ActiveState') in ('active', 'activating', 'deactivating', 'reloading')),
            'WATCHDOG_BUSY')
    if exists and service.get('ActiveState') == 'failed':
        require(not service.get('ControlGroup'), 'WATCHDOG_CGROUP_BUSY')
        run('/usr/bin/systemctl', 'reset-failed', state['timer'][:-6] + '.service')


def require_no_orphans():
    out = run('/usr/bin/systemctl', 'list-units', '--all', '--plain', '--no-legend', '--no-pager',
              'opsdrill-n03-recover-*.timer', 'opsdrill-n03-recover-*.service')
    require(not out.strip(), 'ORPHAN_WATCHDOG')
    gate_present()
    for name in os.listdir(ROOT):
        if name == LOCK:
            continue
        match = re.fullmatch(r'helper-([0-9a-f]{64})\.py', name)
        require(match is not None, 'ORPHAN_STATE_FILE')
        data, st = read_secure(ROOT / name)
        require(stat.S_IMODE(st.st_mode) == 0o600 and hashlib.sha256(data).hexdigest() == match.group(1),
                'HELPER_CHANGED')


def timing_record(rid, status=502):
    require(isinstance(rid, str) and re.fullmatch(r'[0-9a-f]{32}', rid), 'BAD_REQUEST_ID')
    path = pathlib.Path('/var/log/nginx/orderguard-timing.log')
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'UNSAFE_TIMING_LOG')
            os.lseek(fd, max(0, st.st_size - 262144), os.SEEK_SET)
            data = os.read(fd, 262144).decode('utf-8')
        finally: os.close(fd)
        for line in data.splitlines():
            try: obj = json.loads(line)
            except ValueError: continue
            if obj.get('request_id') == rid:
                require(obj.get('status') == str(status) and obj.get('method') == 'GET' and
                        'request_time' in obj and 'upstream_response_time' in obj, 'BAD_GATEWAY_TIMING')
                if status == 504:
                    require(float(obj['request_time']) >= 8 and float(obj['upstream_response_time']) >= 8,
                            'BAD_504_TIMING')
                return
        time.sleep(0.05)
    raise Refused('TIMING_RECORD_MISSING')


def restore_service(state):
    p, digest = service_identity()
    require(digest == state['service_sha'], 'SERVICE_CONFIG_CHANGED')
    if p.get('ActiveState') == 'active':
        wait_ready()
        return 'ALREADY_ACTIVE'
    require(p.get('ActiveState') == 'inactive' and p.get('SubState') == 'dead' and p.get('MainPID') == '0',
            'SERVICE_STATE_AMBIGUOUS')
    run('/usr/bin/systemctl', 'start', SERVICE, timeout=20)
    wait_ready()
    return 'STARTED'


def validate_binding(rid, owner_id):
    require(isinstance(rid, str) and RID.fullmatch(rid) and
            isinstance(owner_id, str) and OWNER.fullmatch(owner_id), 'BAD_C01_BINDING')


def authorize_state(state, binding=None):
    # Called only while holding the same lock as state reads and all effects.
    if binding is None:
        require('owner_kind' not in state and 'owner_id' not in state, 'C01_OWNS_N03')
        return
    rid, owner_id = binding
    validate_binding(rid, owner_id)
    require(state.get('kind') == 'n03-502' and state.get('run_id') == rid and
            state.get('owner_kind') == 'C01_APP_DOWN_V1' and state.get('owner_id') == owner_id and
            state.get('timer') == 'opsdrill-n03-recover-' + rid + '.timer', 'C01_OWNER_MISMATCH')


def inject(cli_receipt=False, variant='502', binding=None):
    guard()
    require(variant in ('502', '504'), 'BAD_VARIANT')
    if binding is not None:
        require(variant == '502' and not cli_receipt, 'BAD_C01_VARIANT')
        validate_binding(*binding)
    with locked() as dfd:
        require(read_state(dfd) is None, 'PREVIOUS_RUN_REQUIRES_RESET')
        require_no_orphans()
        p, digest = service_identity()
        require(p.get('ActiveState') == 'active' and p.get('SubState') == 'running' and
                p.get('MainPID', '').isdigit() and int(p['MainPID']) > 0 and
                re.fullmatch(r'[0-9a-f]{32}', p.get('InvocationID', '')), 'SERVICE_NOT_READY')
        require(ready(), 'BASELINE_NOT_READY')
        if variant == '504':
            require(request(8080, '/api/v1/orders/slow')[0] == 404, 'SLOW_ENDPOINT_NOT_CLOSED')
        helper, helper_sha = install_helper(dfd)
        rid = binding[0] if binding is not None else secrets.token_hex(12)
        state = {'version': 1, 'kind': 'n03-' + variant, 'run_id': rid, 'phase': 'PREPARING',
                 'timer': 'opsdrill-n03-recover-' + rid + '.timer', 'helper': helper, 'helper_sha': helper_sha,
                 'service_sha': digest, 'boot_id': BOOT_ID.read_text(encoding='ascii').strip(),
                 'original_pid': int(p['MainPID']), 'original_invocation': p['InvocationID']}
        if binding is not None:
            state.update(owner_kind='C01_APP_DOWN_V1', owner_id=binding[1])
        if variant == '504':
            created = time.monotonic_ns()
            state.update(gate_created_ns=created, gate_expires_ns=created + GATE_TTL_SECONDS * 1_000_000_000)
        write_state(dfd, state)
        arm_watchdog(state)
        current, digest_now = service_identity()
        require(digest_now == digest and current.get('ActiveState') == 'active' and
                current.get('MainPID') == str(state['original_pid']) and
                current.get('InvocationID') == state['original_invocation'], 'SERVICE_CHANGED_BEFORE_INJECT')
        state['phase'] = 'STOP_REQUESTED' if variant == '502' else 'GATE_REQUESTED'
        write_state(dfd, state)
        require_watchdog_armed(state)
        if variant == '502':
            run('/usr/bin/systemctl', 'stop', SERVICE, timeout=15)
            stopped, digest_now = service_identity()
            require(digest_now == digest and stopped.get('ActiveState') == 'inactive' and
                    stopped.get('SubState') == 'dead' and stopped.get('MainPID') == '0', 'SERVICE_NOT_STOPPED')
            with socket.socket() as sock:
                sock.settimeout(2)
                require(sock.connect_ex(('127.0.0.1', 8000)) == errno.ECONNREFUSED, 'UPSTREAM_PORT_NOT_REFUSED')
            code, request_id = request(8080, '/health')
            require(code == 502, 'EXPECTED_502_NOT_OBSERVED')
            timing_record(request_id)
        else:
            create_gate(state)
            started = time.monotonic()
            code, request_id = request(8080, '/api/v1/orders/slow', timeout=15)
            elapsed = time.monotonic() - started
            require(code == 504 and 8 <= elapsed < 15, 'EXPECTED_504_NOT_OBSERVED')
            timing_record(request_id, 504)
            require(gate_present(state) and gate_live(state) and ready(), 'GATE_OR_SERVICE_CHANGED')
        state['phase'] = 'FAULT'
        if binding is not None:
            state['c01_fault_confirmed'] = True
        write_state(dfd, state)
        result = {'receipt': 'N03_' + variant + '_OWNER_V1', 'run_id': rid, 'timer': state['timer']} if cli_receipt else \
                 {'status': 'N03_' + variant + '_PRESENT', 'run_id': rid, 'watchdog_seconds': WATCHDOG_SECONDS,
                  'nginx_status': int(variant), 'upstream': 'connection_refused' if variant == '502' else 'response_timeout',
                  'timing': 'matched'}
        if binding is not None:
            result = {'kind': 'C01_APP_DOWN_V1', 'owner_id': binding[1], 'run_id': rid, 'timer': state['timer']}
        print(json.dumps(result))
        return 0


def check(expected=None, binding=None):
    guard()
    with locked() as dfd:
        state = read_state(dfd)
        require(state is not None and (expected is None or state['run_id'] == expected), 'RUN_ID_MISMATCH')
        authorize_state(state, binding)
        if binding is not None:
            require(state.get('c01_fault_confirmed') is True and state['phase'] in ('FAULT', 'WATCHDOG_HEALTHY'),
                    'C01_FAULT_NOT_CONFIRMED')
            helper_verified(state)
        p, digest = service_identity()
        require(digest == state['service_sha'], 'SERVICE_CONFIG_CHANGED')
        if state['kind'] == 'n03-504':
            require(p.get('ActiveState') == 'active' and ready(), 'SERVICE_NOT_READY')
            if gate_present(state) and gate_live(state):
                print(json.dumps({'status': 'FAULT_PRESENT', 'gate': 'active'})); return 1
            require(request(8080, '/api/v1/orders/slow')[0] == 404, 'SLOW_ENDPOINT_NOT_CLOSED')
            print(json.dumps({'status': 'RECOVERED', 'health': 200, 'ready': 200})); return 0
        if p.get('ActiveState') == 'active' and ready():
            print(json.dumps({'status': 'RECOVERED', 'health': 200, 'ready': 200})); return 0
        if p.get('ActiveState') == 'inactive':
            if binding is not None:
                require(p.get('SubState') == 'dead' and p.get('MainPID') == '0', 'SERVICE_STATE_AMBIGUOUS')
            code, _ = request(8080, '/health')
            require(code == 502, 'UNEXPECTED_GATEWAY_STATUS')
            print(json.dumps({'status': 'FAULT_PRESENT', 'nginx_status': 502})); return 1
        raise Refused('SERVICE_STATE_AMBIGUOUS')


def watchdog(rid, owner_id=None):
    guard()
    require(isinstance(rid, str) and RID.fullmatch(rid), 'BAD_RUN_ID')
    if owner_id is not None:
        validate_binding(rid, owner_id)
    with locked() as dfd:
        state = read_state(dfd)
        if state is None: return 0
        require(state['run_id'] == rid, 'RUN_ID_MISMATCH')
        authorize_state(state, None if owner_id is None else (rid, owner_id))
        helper_verified(state)
        require(CODE == helper_path(state), 'WATCHDOG_PATH_MISMATCH')
        if state['phase'] == 'PREPARING':
            gate_present()
            p, digest = service_identity()
            require(digest == state['service_sha'] and p.get('ActiveState') == 'active' and ready(), 'PREPARE_SERVICE_CHANGED')
            state.update(phase='WATCHDOG_HEALTHY', watchdog_action='PREPARE_OBSERVED_ACTIVE')
            write_state(dfd, state)
            return 0
        if state['kind'] == 'n03-504':
            removed = remove_gate(state)
            p, digest = service_identity()
            require(digest == state['service_sha'] and p.get('ActiveState') == 'active', 'SERVICE_CONFIG_CHANGED')
            wait_ready()
            require(request(8080, '/api/v1/orders/slow')[0] == 404, 'SLOW_ENDPOINT_NOT_CLOSED')
            outcome = 'GATE_REMOVED' if removed else 'GATE_ALREADY_ABSENT'
        else:
            outcome = restore_service(state)
        state.update(phase='WATCHDOG_HEALTHY', watchdog_action=outcome)
        write_state(dfd, state)
        print(json.dumps({'status': 'WATCHDOG_HEALTHY', 'action': outcome}))
        return 0


def reset(expected=None, binding=None):
    guard()
    with locked() as dfd:
        state = read_state(dfd)
        if state is None:
            require(binding is None and expected is None, 'RUN_ID_MISMATCH')
            require_no_orphans()
            p, _ = service_identity()
            require(p.get('ActiveState') == 'active' and ready(), 'SERVICE_NOT_READY')
            print(json.dumps({'status': 'ALREADY_CLEAN'})); return 0
        require(expected is None or state['run_id'] == expected, 'RUN_ID_MISMATCH')
        authorize_state(state, binding)
        helper_verified(state)
        if state['phase'] == 'PREPARING':
            gate_present()
            p, digest = service_identity()
            require(digest == state['service_sha'] and p.get('ActiveState') == 'active' and ready(), 'PREPARE_SERVICE_CHANGED')
            outcome = 'ALREADY_ACTIVE'
        elif state['kind'] == 'n03-504':
            removed = remove_gate(state)
            p, digest = service_identity()
            require(digest == state['service_sha'] and p.get('ActiveState') == 'active', 'SERVICE_CONFIG_CHANGED')
            wait_ready()
            require(request(8080, '/api/v1/orders/slow')[0] == 404, 'SLOW_ENDPOINT_NOT_CLOSED')
            outcome = 'GATE_REMOVED' if removed else 'GATE_ALREADY_ABSENT'
        else:
            outcome = restore_service(state)
        cancel_watchdog(state)
        os.unlink(STATE, dir_fd=dfd)
        os.fsync(dfd)
        print(json.dumps({'status': 'CLEANUP_PASS', 'run_id': state['run_id'], 'service_action': outcome}))
        return 0


def verify_owner(rid, timer):
    guard()
    require(bool(RID.fullmatch(rid)) and timer == 'opsdrill-n03-recover-' + rid + '.timer', 'BAD_OWNER')
    with locked() as dfd:
        state = read_state(dfd)
        require(state is not None and state['run_id'] == rid and state['timer'] == timer and
                state['phase'] == 'FAULT', 'RUN_ID_MISMATCH')
        authorize_state(state)
        helper_verified(state)
        require_watchdog_armed(state)
        service, digest = service_identity()
        require(digest == state['service_sha'], 'SERVICE_CONFIG_CHANGED')
        if state['kind'] == 'n03-504':
            require(service.get('ActiveState') == 'active' and ready() and gate_present(state) and gate_live(state),
                    'GATE_OR_SERVICE_CHANGED')
        else:
            require(service.get('ActiveState') == 'inactive' and service.get('SubState') == 'dead' and
                    service.get('MainPID') == '0', 'SERVICE_STATE_AMBIGUOUS')
            code, _ = request(8080, '/health')
            require(code == 502, 'EXPECTED_502_NOT_OBSERVED')
    print(json.dumps({'status': 'OWNER_VERIFIED', 'run_id': rid, 'timer': timer}))
    return 0


def inspect_clean():
    guard()
    with locked() as dfd:
        require(read_state(dfd) is None, 'NOT_CLEAN')
        require_no_orphans()
        service, _ = service_identity()
        require(service.get('ActiveState') == 'active' and ready(), 'SERVICE_NOT_READY')
    print(json.dumps({'status': 'CLEAN'}))
    return 0


def resolve(rid, binding=None):
    guard()
    require(bool(RID.fullmatch(rid)), 'BAD_RUN_ID')
    with locked() as dfd:
        state = read_state(dfd)
        require(state is not None and state['run_id'] == rid and state['kind'] in ('n03-502', 'n03-504') and
                state['phase'] in ('FAULT', 'WATCHDOG_HEALTHY'), 'RUN_ID_MISMATCH')
        authorize_state(state, binding)
        helper_verified(state)
        if state['kind'] == 'n03-502':
            result = {'status': 'MITIGATED', 'service_action': restore_service(state)}
        else:
            removed = remove_gate(state)
            service, digest = service_identity()
            require(digest == state['service_sha'] and service.get('ActiveState') == 'active', 'SERVICE_CONFIG_CHANGED')
            wait_ready()
            require(request(8080, '/api/v1/orders/slow')[0] == 404, 'SLOW_ENDPOINT_NOT_CLOSED')
            result = {'status': 'MITIGATED', 'gate_removed': removed}
    print(json.dumps(result))
    return 0


def main(argv):
    require(len(argv) >= 2, 'USAGE')
    action = argv[1]
    if action == 'watchdog':
        require(len(argv) in (3, 4), 'USAGE')
        return watchdog(*argv[2:])
    if action in ('c01-inject', 'c01-check', 'c01-resolve', 'c01-reset'):
        require(len(argv) == 4, 'USAGE')
        binding = (argv[2], argv[3])
        validate_binding(*binding)
        if action == 'c01-inject': return inject(binding=binding)
        if action == 'c01-check': return check(binding[0], binding)
        if action == 'c01-resolve': return resolve(binding[0], binding)
        return reset(binding[0], binding)
    if action == 'inject':
        args = argv[2:]
        require(args in ([], ['--cli'], ['--504'], ['--504', '--cli']), 'USAGE')
        return inject('--cli' in args, '504' if '--504' in args else '502')
    if action == 'verify-owner':
        require(len(argv) == 4, 'USAGE')
        return verify_owner(argv[2], argv[3])
    if action == 'inspect-clean':
        require(len(argv) == 2, 'USAGE')
        return inspect_clean()
    if action == 'resolve':
        require(len(argv) == 3, 'USAGE')
        return resolve(argv[2])
    require(action in ('check', 'reset') and len(argv) in (2, 3), 'USAGE')
    if len(argv) == 3:
        require(bool(RID.fullmatch(argv[2])), 'BAD_RUN_ID')
    return {'check': check, 'reset': reset}[action](*(argv[2:] or []))


if __name__ == '__main__':
    try: sys.exit(main(sys.argv))
    except (Refused, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL_CLOSED', 'error': str(exc) if isinstance(exc, Refused) else type(exc).__name__}), file=sys.stderr)
        sys.exit(2)
