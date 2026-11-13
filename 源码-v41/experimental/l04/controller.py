#!/usr/bin/env python3
"""Candidate L04 controller. Requires a trusted root-owned installation on Linux."""
import contextlib
try:
    import fcntl
except ImportError:
    fcntl = None
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time

SCRIPT = Path(os.path.abspath(__file__))
HERE = SCRIPT.parent
WORKER = HERE / 'service.py'
STATE_DIR = HERE / 'runtime'
PYTHON = '/usr/bin/python3'
SYSTEMCTL = '/usr/bin/systemctl'
SYSTEMD_RUN = '/usr/bin/systemd-run'
RID = re.compile(r'^[0-9a-f]{24}$')
BOOT = Path('/proc/sys/kernel/random/boot_id')
TTL = 300


class Refused(Exception):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def command(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
    require(p.returncode == 0, 'command failed: ' + args[0])
    return p.stdout


def check_install_path(directory, files):
    for path in (directory, *directory.parents):
        st = path.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'installation path must be root owned and not writable by others')
    for path in files:
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022, 'unsafe installed file')


def secure_install():
    require(sys.platform == 'linux' and fcntl is not None and os.geteuid() == 0, 'Linux root required')
    marker = Path('/etc/opsdrill-lab')
    st = marker.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
            not st.st_mode & 0o022 and st.st_size <= 64 and
            marker.read_bytes().rstrip(b'\n') == b'ops-drill-kit', 'unsafe lab marker')
    require(command('/usr/bin/systemd-detect-virt', '--vm').strip() == 'vmware', 'VMware lab required')
    check_install_path(HERE, (SCRIPT, WORKER))


@contextlib.contextmanager
def locked():
    secure_install()
    try:
        STATE_DIR.mkdir(mode=0o700)
    except FileExistsError:
        pass
    st = STATE_DIR.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700,
            'unsafe runtime directory')
    fd = os.open(STATE_DIR / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) == 0o600, 'unsafe lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused('another operation is running')
        yield
    finally:
        os.close(fd)


def load():
    try:
        fd = os.open(STATE_DIR / 'current.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_size < 4096, 'unsafe state')
        state = json.loads(os.read(fd, 4096))
    finally:
        os.close(fd)
    require(isinstance(state, dict) and RID.fullmatch(state.get('run_id', '')) and
            state.get('phase') in ('STARTING', 'FAULT', 'STOPPING', 'RESOLVING', 'RECOVERED', 'RESETTING'),
            'invalid state')
    return state


def save(state):
    # The locked 0700 directory is root-only. Exclusive temporary files prevent clobbering.
    tmp = STATE_DIR / ('.new-' + secrets.token_hex(12))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(state, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_DIR / 'current.json')
        dfd = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if tmp.exists(): tmp.unlink()


def name(rid, mode):
    require(RID.fullmatch(rid or '') and mode in ('fault', 'fixed'), 'bad identity')
    return 'opsdrill-l04-' + rid + '-' + mode + '.service'


def socket_path(rid):
    require(RID.fullmatch(rid or ''), 'bad run id')
    path = STATE_DIR / (rid + '.sock')
    require(len(os.fsencode(path)) < 104, 'installation path too long for Unix socket')
    return path


def properties(unit):
    keys = ('Id', 'LoadState', 'ActiveState', 'FragmentPath', 'Type', 'User', 'DropInPaths',
            'MainPID', 'InvocationID', 'ControlGroup', 'LimitNOFILE', 'RuntimeMaxUSec')
    out = command(SYSTEMCTL, 'show', '--all', unit, *['--property=' + key for key in keys])
    result = {}
    for line in out.splitlines():
        key, sep, value = line.partition('=')
        require(sep and key not in result, 'invalid systemd properties')
        result[key] = value
    require(result.get('Id') == unit and result.get('LoadState') in ('loaded', 'not-found'),
            'invalid unit identity or load state')
    # A collected transient unit may expose only generic unit properties.
    if result['LoadState'] == 'loaded':
        require(set(result) == set(keys), 'incomplete systemd properties')
    else:
        require(result.get('ActiveState', 'inactive') == 'inactive' and
                result.get('MainPID', '0') in ('', '0'), 'not-found unit still active')
    return result


def absent(unit):
    return properties(unit)['LoadState'] == 'not-found'


def finished_path(rid):
    require(isinstance(rid, str) and RID.fullmatch(rid), 'bad run id')
    return STATE_DIR / ('done-' + rid + '.json')


def finished(rid):
    try:
        fd = os.open(finished_path(rid), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_size < 1024, 'unsafe completion receipt')
        data = json.loads(os.read(fd, 1024))
        require(data == {'receipt': 'L04_CLEANUP_V1', 'run_id': rid}, 'invalid completion receipt')
        return True
    finally:
        os.close(fd)


def sync_dir():
    fd = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)


def record_finished(rid):
    # A root-only, exclusive receipt records only an already confirmed cleanup.
    fd = os.open(finished_path(rid), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump({'receipt': 'L04_CLEANUP_V1', 'run_id': rid}, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    sync_dir()


def confirmed_gone(rid):
    require(absent(name(rid, 'fault')) and absent(name(rid, 'fixed')) and
            not os.path.lexists(socket_path(rid)), 'completed run has remaining or ambiguous objects')


def wait_gone(rid):
    # systemd may release a stopped transient unit shortly after stop returns.
    for attempt in range(21):
        if absent(name(rid, 'fault')) and absent(name(rid, 'fixed')) and not os.path.lexists(socket_path(rid)):
            return
        if attempt < 20: time.sleep(0.1)
    raise Refused('owned objects not collected; inspect retained state')


def identity(state):
    rid, mode = state['run_id'], state['mode']
    unit = name(rid, mode)
    p = properties(unit)
    require(state.get('boot') == BOOT.read_text().strip(), 'boot changed')
    require(p['Id'] == unit and p['LoadState'] == 'loaded' and p['ActiveState'] == 'active' and
            p['FragmentPath'] == '/run/systemd/transient/' + unit and p['Type'] == 'exec' and
            p['User'] in ('', 'root') and not p['DropInPaths'] and
            p['ControlGroup'] == '/system.slice/' + unit and
            p['InvocationID'] == state.get('invocation') and re.fullmatch(r'[0-9a-f]{32}', p['InvocationID']) and
            p['MainPID'] == str(state.get('pid')) and p['MainPID'].isdigit() and int(p['MainPID']) > 1 and
            p['LimitNOFILE'] == str(32 if mode == 'fault' else 128) and
            p['RuntimeMaxUSec'] in ('5min', '5min 0', '300s'), 'unit identity changed')
    pid = int(p['MainPID'])
    argv = Path('/proc/%d/cmdline' % pid).read_bytes().split(b'\0')
    require(argv == [os.fsencode(PYTHON), os.fsencode(WORKER), os.fsencode(socket_path(rid)), b''],
            'service command changed')
    limits = Path('/proc/%d/limits' % pid).read_text()
    match = re.search(r'^Max open files\s+(\d+)\s+(\d+)\s+files\s*$', limits, re.MULTILINE)
    expected = 32 if mode == 'fault' else 128
    require(match and int(match[1]) == expected and int(match[2]) == expected, 'process limit mismatch')
    return p


def probe(state):
    identity(state)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        s.connect(str(socket_path(state['run_id'])))
        s.sendall(b'probe\n')
        data = s.recv(1024)
    result = json.loads(data)
    require(isinstance(result, dict) and result.get('health') == 'ok', 'health probe failed')
    identity(state)
    return result


def verify_result(state, result):
    if state['mode'] == 'fault':
        require(result.get('errno') == 24 and result.get('opened', 48) < 48, 'EMFILE not observed')
    else:
        require(result.get('errno') is None and result.get('opened') == 48, 'recovery probe failed')


def launch(state, mode):
    rid = state['run_id']
    unit = name(rid, mode)
    require(properties(unit)['LoadState'] == 'not-found', 'unit already exists')
    require(not os.path.lexists(socket_path(rid)), 'socket already exists')
    state.update(phase='STARTING' if mode == 'fault' else 'RESOLVING', mode=mode)
    save(state)
    command(SYSTEMD_RUN, '--unit=' + unit, '--service-type=exec', '--property=LimitNOFILE=' +
            ('32:32' if mode == 'fault' else '128:128'), '--property=RuntimeMaxSec=300',
            '--property=MemoryMax=64M', '--property=TasksMax=8', '--property=NoNewPrivileges=yes',
            PYTHON, str(WORKER), str(socket_path(rid)))
    p = properties(unit)
    require(p['MainPID'].isdigit() and int(p['MainPID']) > 1 and re.fullmatch(r'[0-9a-f]{32}', p['InvocationID']),
            'service did not establish identity')
    state.update(pid=int(p['MainPID']), invocation=p['InvocationID'])
    # Persist identity before probing. Interrupted starts remain explicitly ambiguous.
    save(state)
    for _ in range(40):
        if os.path.exists(socket_path(rid)): break
        time.sleep(0.05)
    result = probe(state)
    verify_result(state, result)
    state['phase'] = 'FAULT' if mode == 'fault' else 'RECOVERED'
    save(state)


def owned(state, rid, phases):
    require(state is not None and RID.fullmatch(rid or '') and state['run_id'] == rid and
            state['phase'] in phases, 'run or phase mismatch; inspect retained state')
    identity(state)


def stop(state):
    identity(state)
    command(SYSTEMCTL, 'stop', name(state['run_id'], state['mode']))
    p = properties(name(state['run_id'], state['mode']))
    if p['LoadState'] != 'not-found':
        require(p['ActiveState'] == 'inactive' and p['MainPID'] == '0' and
                p['InvocationID'] == state['invocation'] and
                p['FragmentPath'] == '/run/systemd/transient/' + name(state['run_id'], state['mode']),
                'stop not confirmed')
    # Worker removes its own socket on clean shutdown; never unlink an unknown object.
    require(not os.path.lexists(socket_path(state['run_id'])), 'socket remains; inspect manually')


def action(op, rid=None):
    with locked():
        state = load()
        if op == 'start':
            require(state is None, 'existing state requires inspection or reset')
            rid = secrets.token_hex(12)
            require(not finished(rid), 'run id already used')
            state = {'run_id': rid, 'boot': BOOT.read_text().strip(), 'phase': 'STARTING'}
            launch(state, 'fault')
            return 0, {'receipt': 'L04_RUN_OWNER_V1', 'run_id': rid, 'unit': name(rid, 'fault')}
        if op == 'reset' and finished(rid):
            confirmed_gone(rid)
            if state is not None and state['run_id'] == rid:
                require(state['phase'] == 'RESETTING', 'receipt conflicts with current run')
                (STATE_DIR / 'current.json').unlink()
                sync_dir()
            return 0, {'status': 'ALREADY_CLEAN', 'run_id': rid}
        owned(state, rid, ('FAULT', 'RECOVERED'))
        if op == 'verify-owner':
            require(state['phase'] == 'FAULT', 'fault phase required')
            verify_result(state, probe(state))
            return 0, {'status': 'OWNER_VERIFIED', 'run_id': rid}
        if op == 'check':
            result = probe(state)
            verify_result(state, result)
            return (1 if state['phase'] == 'FAULT' else 0), {'status': state['phase'], 'probe': result}
        if op == 'resolve':
            require(state['phase'] == 'FAULT', 'fault phase required')
            verify_result(state, probe(state))
            state['phase'] = 'STOPPING'; save(state)
            stop(state)
            launch(state, 'fixed')
            return 0, {'status': 'RECOVERED', 'run_id': rid, 'unit': name(rid, 'fixed')}
        if op == 'reset':
            state['phase'] = 'RESETTING'; save(state)
            stop(state)
            wait_gone(rid)
            record_finished(rid)
            (STATE_DIR / 'current.json').unlink()
            sync_dir()
            return 0, {'status': 'CLEANUP_PASS', 'run_id': rid}
        raise Refused('unsupported action')


def main():
    require(len(sys.argv) in (2, 3), 'usage: controller.py start | check|resolve|reset|verify-owner RUN_ID')
    op = sys.argv[1]
    require((op == 'start' and len(sys.argv) == 2) or
            (op in ('check', 'resolve', 'reset', 'verify-owner') and len(sys.argv) == 3), 'invalid action')
    rc, result = action(op, sys.argv[2] if len(sys.argv) == 3 else None)
    print(json.dumps(result))
    return rc


if __name__ == '__main__':
    try: sys.exit(main())
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'FAIL_CLOSED', 'error': str(exc)}), file=sys.stderr)
        sys.exit(2)
