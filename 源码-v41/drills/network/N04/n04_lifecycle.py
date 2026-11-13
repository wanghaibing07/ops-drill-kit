#!/usr/bin/env python3
"""Experimental N04 cross-process lifecycle; Linux/systemd only."""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time

ROOT = Path('/run/opsdrill-n04')
INSTALL = Path('/usr/local/libexec/opsdrill/n04')
PYTHON = '/usr/bin/python3'
SYSTEMCTL = '/usr/bin/systemctl'
SYSTEMD_RUN = '/usr/bin/systemd-run'
UNSHARE = '/usr/bin/unshare'
RID = re.compile(r'[0-9a-f]{24}\Z')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}
MAX_MESSAGE = 8192
SERVICE_SECONDS = 90


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def guard():
    require(os.geteuid() == 0, 'root required')
    fd = os.open('/etc/opsdrill-lab', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= 64 and
                os.read(fd, 65).strip() == b'ops-drill-kit', 'unsafe lab marker')
    finally:
        os.close(fd)
    result = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=ENV, timeout=10, check=False)
    require(result.returncode == 0 and result.stdout.strip() == 'vmware', 'VMware guest required')


def valid_id(rid):
    return isinstance(rid, str) and RID.fullmatch(rid) is not None


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def unit_name(rid):
    require(valid_id(rid), 'invalid run ID')
    return 'opsdrill-n04-' + rid + '.service'


def secure_dir(path, exact=None):
    st = os.lstat(path)
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
            'unsafe directory: ' + str(path))
    if exact is not None:
        require(stat.S_IMODE(st.st_mode) == exact, 'unexpected directory mode')


def protected_sources():
    require(Path(__file__).absolute() == INSTALL / 'n04_lifecycle.py', 'untrusted installation path')
    paths = [Path(__file__).absolute(), Path(__file__).absolute().with_name('n04.py')]
    result = {}
    for path in paths:
        for parent in path.parents:
            secure_dir(parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                    not st.st_mode & 0o022 and st.st_size <= 1024 * 1024, 'unsafe source')
            with os.fdopen(fd, 'rb') as stream:
                fd = -1
                result[path.name] = hashlib.sha256(stream.read(1024 * 1024 + 1)).hexdigest()
        finally:
            if fd >= 0:
                os.close(fd)
    path = INSTALL / 'manifest.json'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= 1024, 'unsafe installed manifest')
        data = os.read(fd, 1025)
        require(len(data) == st.st_size, 'installed manifest changed')
    finally:
        os.close(fd)
    manifest = json.loads(data, object_pairs_hook=unique)
    require(manifest == result, 'installed module digest mismatch')
    return result


def base(create=False):
    require(os.geteuid() == 0, 'root required')
    secure_dir(Path('/'))
    secure_dir(Path('/run'))
    if create:
        try:
            os.mkdir(ROOT, 0o700)
        except FileExistsError:
            pass
    secure_dir(ROOT, 0o700)
    return ROOT


def run_dir(rid):
    require(valid_id(rid), 'invalid run ID')
    path = base() / rid
    secure_dir(path, 0o700)
    return path


def command(*args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=ENV, timeout=8, check=False)
    require(result.returncode == 0 and len(result.stdout) <= MAX_MESSAGE, 'systemd command failed')
    return result.stdout


def properties(rid):
    names = ('Id', 'LoadState', 'ActiveState', 'MainPID', 'InvocationID', 'Transient',
             'FragmentPath', 'ExecStart', 'ControlGroup')
    output = command(SYSTEMCTL, 'show', unit_name(rid), *('--property=' + name for name in names))
    values = {}
    for line in output.splitlines():
        key, sep, value = line.partition('=')
        require(sep and key not in values, 'invalid systemd properties')
        values[key] = value
    if set(values) != set(names):
        require(values.get('LoadState') == 'not-found' and properties_absent(rid),
                'incomplete systemd properties')
        return {'LoadState': 'not-found'}
    return values


def process_start(pid):
    data = Path('/proc/%d/stat' % pid).read_text(encoding='ascii')
    end = data.rfind(')')
    require(end > 0, 'invalid process stat')
    fields = data[end + 2:].split()
    require(len(fields) > 19 and fields[19].isdigit(), 'missing process start time')
    return int(fields[19])


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None,
            'invalid boot ID')
    return value


def validate_unit(rid, props):
    unit = unit_name(rid)
    path = str(Path(__file__).absolute())
    expected = 'argv[]=' + PYTHON + ' -I -B ' + path + ' serve ' + rid + ' ;'
    require(props.get('Id') == unit and props.get('LoadState') == 'loaded' and
            props.get('ActiveState') == 'active' and props.get('Transient') == 'yes' and
            props.get('FragmentPath') == '/run/systemd/transient/' + unit and
            props.get('ControlGroup') == '/system.slice/' + unit and
            'path=' + PYTHON + ' ;' in props.get('ExecStart', '') and
            expected in props.get('ExecStart', ''), 'unit identity mismatch')
    pid = props.get('MainPID', '')
    invocation = props.get('InvocationID', '')
    require(pid.isascii() and pid.isdigit() and int(pid) > 1 and
            re.fullmatch(r'[0-9a-f]{32}', invocation) is not None, 'unit process identity missing')
    return int(pid), invocation


def identity(rid):
    pid, invocation = validate_unit(rid, properties(rid))
    return {'pid': pid, 'invocation': invocation, 'start_ticks': process_start(pid),
            'boot_id': boot_id(), 'sources': protected_sources()}


def read_record(rid):
    path = run_dir(rid) / 'identity.json'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= MAX_MESSAGE, 'unsafe record')
        raw = os.read(fd, MAX_MESSAGE + 1)
        require(len(raw) == st.st_size, 'record changed')
    finally:
        os.close(fd)
    obj = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(obj, dict) and obj.get('version') == 1 and obj.get('run_id') == rid and
            set(obj) == {'version', 'run_id', 'identity'}, 'invalid record')
    record = obj['identity']
    require(isinstance(record, dict) and set(record) == {'pid', 'invocation', 'start_ticks', 'boot_id', 'sources'} and
            type(record['pid']) is int and record['pid'] > 1 and
            type(record['start_ticks']) is int and record['start_ticks'] > 0 and
            isinstance(record['invocation'], str) and re.fullmatch(r'[0-9a-f]{32}', record['invocation']) and
            isinstance(record['boot_id'], str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', record['boot_id']) and
            isinstance(record['sources'], dict) and set(record['sources']) == {'n04.py', 'n04_lifecycle.py'} and
            all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) for value in record['sources'].values()),
            'invalid recorded identity')
    return record


def save_record(rid, record):
    path = run_dir(rid) / 'identity.json'
    raw = (json.dumps({'version': 1, 'run_id': rid, 'identity': record}, sort_keys=True) + '\n').encode()
    require(len(raw) <= MAX_MESSAGE, 'record too large')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def peer(sock):
    return struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))


def receive_line(sock, limit=MAX_MESSAGE):
    data = b''
    while b'\n' not in data:
        part = sock.recv(min(1024, limit + 1 - len(data)))
        require(bool(part), 'incomplete message')
        data += part
        require(len(data) <= limit, 'message too large')
    require(data.endswith(b'\n') and data.count(b'\n') == 1, 'invalid framing')
    return data[:-1]


def control_socket_identity(rid):
    st = os.lstat(run_dir(rid) / 'control.sock')
    require(stat.S_ISSOCK(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
            stat.S_IMODE(st.st_mode) == 0o600, 'unsafe control socket')
    return st.st_dev, st.st_ino


def request(rid, action, record):
    require(action in ('check', 'resolve', 'reset', 'status'), 'invalid action')
    require(identity(rid) == record, 'worker identity changed')
    path = run_dir(rid) / 'control.sock'
    socket_id = control_socket_identity(rid)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(8)
        client.connect(str(path))
        pid, uid, _ = peer(client)
        require(uid == 0 and pid == record['pid'] and identity(rid) == record, 'control peer identity changed')
        client.sendall((action + '\n').encode('ascii'))
        response = json.loads(receive_line(client), object_pairs_hook=unique)
        require(isinstance(response, dict) and response.get('run_id') == rid and
                response.get('action') == action and isinstance(response.get('ok'), bool), 'invalid response')
        if response['ok']:
            expected = {'status': 'injected', 'check': 'check', 'resolve': 'repair', 'reset': 'reset'}[action]
            require(isinstance(response.get('result'), dict) and response['result'].get('event') == expected,
                    'invalid worker event')
        if action == 'reset' and response['ok']:
            require(control_socket_identity(rid) == socket_id, 'control socket identity changed')
            response['_socket_identity'] = socket_id
        return response


def worker_line(pipe, deadline):
    data = b''
    while b'\n' not in data:
        remaining = deadline - time.monotonic()
        require(remaining > 0 and select.select([pipe], [], [], remaining)[0], 'worker response timeout')
        chunk = os.read(pipe.fileno(), 1)
        require(bool(chunk), 'worker exited')
        data += chunk
        require(len(data) <= MAX_MESSAGE, 'worker response too large')
    result = json.loads(data, object_pairs_hook=unique)
    require(isinstance(result, dict), 'invalid worker response')
    return result


def serve(rid):
    directory = run_dir(rid)
    protected_sources()
    child = subprocess.Popen([UNSHARE, '--net', '--', PYTHON, '-I', '-B',
                              str(Path(__file__).absolute().with_name('n04.py')), '--worker'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env=ENV, close_fds=True)
    server = None
    try:
        initial = worker_line(child.stdout, time.monotonic() + 25)
        require(initial.get('event') == 'injected', 'worker injection failed')
        path = directory / 'control.sock'
        require(not os.path.lexists(path), 'control socket already exists')
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)
        try:
            server.bind(str(path))
        finally:
            os.umask(old_umask)
        st = os.lstat(path)
        require(stat.S_ISSOCK(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600,
                'unsafe created control socket')
        server.listen(4)
        server.settimeout(0.5)
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline and child.poll() is None:
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(2)
                try:
                    _, uid, _ = peer(client)
                    require(uid == 0, 'untrusted client')
                    action = receive_line(client, 32).decode('ascii')
                    require(action in ('status', 'check', 'resolve', 'reset'), 'invalid action')
                    if action == 'status':
                        result = initial
                    else:
                        wire = 'repair' if action == 'resolve' else action
                        child.stdin.write((wire + '\n').encode('ascii'))
                        child.stdin.flush()
                        result = worker_line(child.stdout, time.monotonic() + 7)
                        expected = {'check': 'check', 'resolve': 'repair', 'reset': 'reset'}[action]
                        require(result.get('event') == expected, 'unexpected worker response')
                        if action == 'reset':
                            require(child.wait(timeout=3) == 0 and result.get('range_restored') is True,
                                    'worker reset not confirmed')
                    response = {'run_id': rid, 'action': action, 'ok': True, 'result': result}
                    client.sendall((json.dumps(response, sort_keys=True) + '\n').encode())
                    if action == 'reset':
                        return
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    # Refuse ambiguous requests; never turn an error into a success receipt.
                    continue
    finally:
        if server is not None:
            server.close()
        try:
            child.stdin.close()
        except BrokenPipeError:
            pass
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()  # Direct child only; systemd also bounds the entire cgroup.
            child.wait()


def start():
    expected_sources = protected_sources()
    root = base(create=True)
    rid = os.urandom(12).hex()
    directory = root / rid
    os.mkdir(directory, 0o700)  # Exclusive creation; collision is a failure.
    print('N04 allocated run_id=' + rid, file=sys.stderr, flush=True)
    require(properties_absent(rid), 'unit already exists')
    command(SYSTEMD_RUN, '--unit=opsdrill-n04-' + rid, '--service-type=exec',
            '--property=RuntimeMaxSec=%ds' % SERVICE_SECONDS, '--property=KillMode=control-group',
            '--property=Restart=no', '--property=User=root', '--property=TasksMax=4',
            '--property=MemoryMax=128M', '--property=LimitNOFILE=64', PYTHON, '-I', '-B',
            str(Path(__file__).absolute()), 'serve', rid)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if os.path.lexists(directory / 'control.sock'):
            record = identity(rid)
            require(record['sources'] == expected_sources, 'sources changed during startup')
            response = request(rid, 'status', record)
            save_record(rid, record)
            return {'receipt': 'N04_OWNER_V1', 'run_id': rid, 'initial': response['result']}
        time.sleep(0.2)
    raise RuntimeError('startup not confirmed; run ID retained for manual inspection')


def properties_absent(rid):
    output = command(SYSTEMCTL, 'show', unit_name(rid), '--property=LoadState')
    return output.strip() == 'LoadState=not-found'


def process_absent(pid):
    require(type(pid) is int and pid > 1, 'invalid recorded PID')
    # Confirm procfs is reachable; only ENOENT for the recorded PID is accepted.
    os.stat('/proc/self/stat')
    try:
        os.stat('/proc/%d' % pid)
    except FileNotFoundError:
        return True
    return False


def confirm_stopped(rid, record, socket_id=None):
    deadline = time.monotonic() + 5
    unit = unit_name(rid)
    while time.monotonic() < deadline:
        if properties_absent(rid):
            # This path is valid only after this process received a verified reset
            # response over the socket bound to the recorded service identity.
            require(socket_id is not None and record['boot_id'] == boot_id(), 'reset evidence missing or boot changed')
            require(process_absent(record['pid']), 'recorded PID still exists')
            require(control_socket_identity(rid) == socket_id, 'control socket identity changed')
            require(properties_absent(rid), 'unit changed during inspection')
            require(process_absent(record['pid']), 'recorded PID reappeared')
            require(control_socket_identity(rid) == socket_id, 'control socket identity changed')
            return True
        props = properties(rid)
        if props.get('LoadState') == 'not-found':
            continue
        require(props.get('Id') == unit and props.get('LoadState') == 'loaded' and
                props.get('Transient') == 'yes' and
                props.get('FragmentPath') == '/run/systemd/transient/' + unit and
                props.get('InvocationID') == record['invocation'], 'stopped unit identity unproven')
        if (props.get('ActiveState') == 'inactive' and props.get('MainPID') == '0' and
                not props.get('ControlGroup')):
            return True
        time.sleep(0.1)
    raise RuntimeError('worker exit not confirmed')


def completion_data(rid, record, socket_id):
    require(valid_id(rid), 'invalid completion run ID')
    require(isinstance(socket_id, (tuple, list)) and len(socket_id) == 2 and
            all(type(value) is int and value >= 0 for value in socket_id), 'invalid socket identity')
    return {'version': 2, 'run_id': rid, 'identity': record, 'result': 'reset_confirmed',
            'socket_identity': list(socket_id)}


def completion(rid, record, create=False, socket_id=None):
    path = run_dir(rid) / 'completed.json'
    if create:
        expected = completion_data(rid, record, socket_id)
        data = (json.dumps(expected, sort_keys=True) + '\n').encode()
        require(len(data) <= MAX_MESSAGE, 'completion too large')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                fd = -1
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return True
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= MAX_MESSAGE, 'unsafe completion')
        data = os.read(fd, MAX_MESSAGE + 1)
        require(len(data) == st.st_size, 'completion changed')
    finally:
        os.close(fd)
    obj = json.loads(data, object_pairs_hook=unique)
    require(isinstance(obj, dict) and 'socket_identity' in obj, 'completion identity mismatch')
    expected = completion_data(rid, record, obj['socket_identity'])
    require(obj == expected, 'completion identity mismatch')
    return tuple(obj['socket_identity'])


def repeat_reset(rid, record):
    socket_id = completion(rid, record)
    if socket_id is False:
        return False
    require(record['boot_id'] == boot_id() and record['sources'] == protected_sources(),
            'completed run environment changed')
    require(process_absent(record['pid']) and control_socket_identity(rid) == socket_id,
            'completed process or socket identity changed')
    confirm_stopped(rid, record, socket_id)
    require(process_absent(record['pid']) and control_socket_identity(rid) == socket_id,
            'completed process or socket identity changed')
    return True


def main(argv):
    require(sys.platform == 'linux', 'Linux required')
    guard()
    protected_sources()
    if argv == ['start']:
        print(json.dumps(start(), sort_keys=True))
        return 0
    require(len(argv) == 2 and valid_id(argv[1]), 'expected action and run ID')
    action, rid = argv
    if action == 'serve':
        serve(rid)
        return 0
    require(action in ('check', 'resolve', 'reset'), 'invalid action')
    record = read_record(rid)
    if action == 'reset' and repeat_reset(rid, record):
        print(json.dumps({'run_id': rid, 'action': 'reset', 'ok': True,
                          'service_stopped': True, 'already_completed': True}, sort_keys=True))
        return 0
    response = request(rid, action, record)
    socket_id = response.pop('_socket_identity', None)
    if action == 'reset' and response['ok'] and response.get('result', {}).get('range_restored') is True:
        require(response['result'].get('event') == 'reset' and socket_id is not None, 'reset evidence missing')
        confirm_stopped(rid, record, socket_id)
        completion(rid, record, create=True, socket_id=socket_id)
        response['service_stopped'] = True
    print(json.dumps(response, sort_keys=True))
    if not response['ok'] or not isinstance(response.get('result'), dict):
        return 2
    result = response['result']
    if action == 'check':
        if result.get('repaired') is True:
            return 0
        return 1 if result.get('fault_proven') is True else 2
    if action == 'resolve':
        return 0 if (result.get('range_restored') is True and result.get('reuse_passed') is True and
                     result.get('requests_on_one_connection') == 8) else 2
    return 0 if result.get('range_restored') is True and response.get('service_stopped') is True else 2


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('N04 lifecycle refused:', exc, file=sys.stderr, flush=True)
        sys.exit(2)
