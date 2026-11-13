#!/usr/bin/env python3
"""N01 independent recovery candidate; fail closed when ownership is uncertain."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path('/run/opsdrill-n01')
SELF = Path('/usr/local/libexec/opsdrill/n01/n01_watchdog.py')
N02 = Path('/usr/local/libexec/opsdrill/n02/n02.py')
N02_SHA = 'a22e59d0217ab059b6c32f985094f074d8d553a273c2d3a2cc4065360d3120dc'
PYTHON = '/usr/bin/python3'
DELAY = 240
MAX_ATTEMPTS = 8
RETRY_INTERVAL = 30
LOCK_TIMEOUT = 5
NAMES = ('od-client', 'od-router', 'od-server')


class Refused(Exception): pass
class RetryLater(Refused): pass


def valid_id(rid):
    if not isinstance(rid, str) or not re.fullmatch(r'[0-9a-f]{24}', rid): raise Refused('invalid run ID')
    return rid


def secure_source(path, digest=None):
    for part in (path, *path.parents):
        st = part.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused('unsafe executable path')
        if part != path and not stat.S_ISDIR(st.st_mode): raise Refused('invalid executable parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_mode & 0o022 or st.st_size > 1048576:
            raise Refused('unsafe executable')
        data = f.read(1048577)
    actual = hashlib.sha256(data).hexdigest()
    if digest is not None and actual != digest: raise Refused('executable digest mismatch')
    return actual


def n02_module():
    secure_source(N02, N02_SHA)
    spec = importlib.util.spec_from_file_location('n02_watchdog_reviewed', N02)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def safe_root(path):
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise Refused('unsafe protected runtime directory')


def file_identity(path, kind):
    st = path.lstat()
    expected = stat.S_ISSOCK(st.st_mode) if kind == 'socket' else stat.S_ISREG(st.st_mode)
    if not expected or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
        raise Refused('unsafe private object')
    if st.st_nlink != 1: raise Refused('unsafe file links')
    return [st.st_dev, st.st_ino, st.st_ctime_ns]


def read_protected(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > limit):
            raise Refused('unsafe protected file')
        data = f.read(limit + 1)
    if len(data) > limit: raise Refused('oversized protected file')
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out: raise Refused('duplicate protected field')
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=unique)


def manifest_path(rid): return ROOT / ('watchdog-' + valid_id(rid) + '.json')


def namespace_identity(name):
    if name not in NAMES: raise Refused('unexpected namespace')
    st = (Path('/run/netns')/name).stat()
    return [st.st_dev, st.st_ino, st.st_ctime_ns]


def check_namespaces(obj):
    for name in NAMES:
        if namespace_identity(name) != obj['namespace_ids'][name]:
            raise Refused('namespace identity changed')


def timer_name(rid): return 'opsdrill-n01-recover-' + valid_id(rid) + '.timer'


def verify_timer(n02, rid):
    timer_name_ = timer_name(rid)
    service_name = timer_name_[:-6] + '.service'
    timer = n02.systemd_properties(timer_name_, ('Id','LoadState','ActiveState','SubState','Triggers','Transient','FragmentPath'))
    service = n02.systemd_properties(service_name, ('Id','LoadState','ActiveState','Transient','FragmentPath','ExecStart','User'))
    # ExecStart can contain multiple commands. A matching substring alone must
    # not allow an additional command or a modified executable to slip past.
    fields = [part.strip().lstrip('{').strip() for part in service['ExecStart'].split(';')]
    paths = [part[5:].strip() for part in fields if part.startswith('path=')]
    argvs = [part[7:].strip() for part in fields if part.startswith('argv[]=')]
    expected_argv = PYTHON + ' -I -B ' + str(SELF) + ' recover ' + rid
    if (timer['Id'] != timer_name_ or timer['LoadState'] != 'loaded' or timer['ActiveState'] != 'active'
            or timer['SubState'] != 'waiting' or timer['Triggers'] != service_name or timer['Transient'] != 'yes'
            or timer['FragmentPath'] != '/run/systemd/transient/' + timer_name_):
        raise Refused('timer identity or activation mismatch')
    if (service['Id'] != service_name or service['LoadState'] != 'loaded' or service['Transient'] != 'yes'
            or service['FragmentPath'] != '/run/systemd/transient/' + service_name or service['User'] != 'root'
            or paths != [PYTHON] or argvs != [expected_argv]):
        raise Refused('service identity mismatch')


def arm(n02, state, topology, resolver_identity, socket_identity):
    """Called while the N01 supervisor holds N02's lock, before service injection."""
    rid = valid_id(state['run_id'])
    safe_root(ROOT); safe_root(n02.ROOT)
    own_sha = secure_source(SELF)
    if topology != n02.load() or topology['run_id'] != state['n02_run_id']:
        raise Refused('N02 state mismatch before arm')
    n02.validate_owned(topology, complete=True); n02.check_table(topology, 'baseline')
    resolver = file_identity(ROOT/'resolv.conf', 'file')
    sock = file_identity(ROOT/'control.sock', 'socket')
    if (read_protected(ROOT/'state.json', 8192) != state
            or resolver[:2] != list(resolver_identity) or sock[:2] != list(socket_identity)):
        raise Refused('private ownership mismatch before arm')
    unit = timer_name(rid)
    if os.path.lexists(ROOT/('completed-'+rid+'.json')): raise Refused('run ID already completed')
    if n02.systemd_properties(unit, ('LoadState',))['LoadState'] != 'not-found': raise Refused('timer already exists')
    namespace_ids = {name:namespace_identity(name) for name in NAMES}
    if any(namespace_ids[name][1] != topology['namespaces'][name] for name in NAMES):
        raise Refused('namespace identity mismatch before arm')
    manifest = {'version':1, 'run_id':rid, 'state':state, 'topology':topology, 'namespace_ids':namespace_ids,
                'state_file':file_identity(ROOT/'state.json','file'),
                'resolver':resolver, 'socket':sock,
                'helper_sha256':own_sha, 'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    check_private(manifest)
    fd = os.open(manifest_path(rid), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, sort_keys=True); f.flush(); os.fsync(f.fileno())
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)
    subprocess.run(['/usr/bin/systemd-run','--unit='+unit[:-6], '--on-active='+str(DELAY)+'s',
                    '--timer-property=AccuracySec=1s', '--service-type=exec', '--property=User=root',
                    PYTHON, '-I', '-B', str(SELF), 'recover', rid], capture_output=True, text=True, timeout=10, check=True)
    verify_timer(n02, rid)


def validate_manifest(obj, rid):
    fields = {'version','run_id','state','topology','namespace_ids','state_file','resolver','socket','helper_sha256','boot_id'}
    if not isinstance(obj, dict) or set(obj) != fields or type(obj['version']) is not int or obj['version'] != 1 or obj['run_id'] != rid:
        raise Refused('invalid recovery manifest')
    if (not isinstance(obj['state'], dict) or obj['state'].get('run_id') != rid
            or not isinstance(obj['topology'], dict) or obj['topology'].get('run_id') != obj['state'].get('n02_run_id')
            or type(obj['state'].get('pid')) is not int or obj['state']['pid'] < 2
            or not re.fullmatch(r'[0-9a-f]{64}', obj.get('helper_sha256',''))):
        raise Refused('invalid recovery identity')
    valid_id(obj['topology']['run_id'])
    if (not isinstance(obj['namespace_ids'], dict) or set(obj['namespace_ids']) != set(NAMES)
            or not isinstance(obj['topology'].get('namespaces'), dict)
            or set(obj['topology']['namespaces']) != set(NAMES)):
        raise Refused('invalid namespace identities')
    for name, value in obj['namespace_ids'].items():
        if (not isinstance(value, list) or len(value) != 3 or any(type(x) is not int or x < 0 for x in value)
                or obj['topology'].get('namespaces', {}).get(name) != value[1]):
            raise Refused('invalid namespace identity')
    for name in ('state_file','resolver','socket'):
        if not isinstance(obj[name], list) or len(obj[name]) != 3 or any(type(x) is not int or x < 0 for x in obj[name]):
            raise Refused('invalid private object identity')
    if not isinstance(obj['boot_id'], str) or not re.fullmatch(r'[0-9a-f-]{36}', obj['boot_id']): raise Refused('invalid boot identity')


def check_private(obj):
    state_path = ROOT/'state.json'
    if file_identity(state_path,'file') != obj['state_file'] or read_protected(state_path,8192) != obj['state']:
        raise Refused('N01 state changed')
    if file_identity(ROOT/'resolv.conf','file') != obj['resolver'] or file_identity(ROOT/'control.sock','socket') != obj['socket']:
        raise Refused('N01 private file identity changed')
    fd = os.open(ROOT/'resolv.conf', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if ([st.st_dev, st.st_ino, st.st_ctime_ns] != obj['resolver'] or not stat.S_ISREG(st.st_mode)
                or st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600
                or f.read(128) != b'nameserver 10.203.1.1\noptions timeout:1 attempts:1\n'):
            raise Refused('resolver content or identity changed')


def record_completion(rid):
    path = ROOT/('completed-'+valid_id(rid)+'.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump({'version':1,'run_id':rid,'result':'clean'}, f, sort_keys=True)
        f.flush(); os.fsync(f.fileno())
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try: os.fsync(fd)
    finally: os.close(fd)


def already_completed(rid):
    path = ROOT/('completed-'+valid_id(rid)+'.json')
    if not os.path.lexists(path): return False
    value = read_protected(path, 512)
    if (not isinstance(value, dict) or value != {'version':1,'run_id':rid,'result':'clean'}
            or type(value.get('version')) is not int): raise Refused('invalid completion receipt')
    return True


def cleanup_owned(n02, obj):
    """Lock must already be held; never signal any process."""
    topology = obj['topology']
    check_private(obj)
    if n02.load() != topology: raise Refused('N02 ownership changed')
    n02.validate_owned(topology, complete=True); n02.check_table(topology, 'baseline'); check_namespaces(obj)
    # N01 creates an unmodified N02 topology and never owns an N02 watchdog.
    # N02.cleanup otherwise permits deleting an unrecorded matching helper;
    # this candidate refuses it because its identity was never captured here.
    if (topology.get('intent') is not False or topology.get('injected') is not None
            or any(topology.get(k) is not None for k in ('timer','helper_sha256','armed_at'))
            or os.path.lexists(n02.helper_path(topology['run_id']))):
        raise Refused('unexpected N02 auxiliary resource')
    for name in n02.NAMES:
        if n02.run(n02.IP, 'netns', 'pids', name, capture=True).stdout.strip():
            raise RetryLater('namespace contains processes')
    # N02 validates identities and rechecks for processes during deletion.
    check_namespaces(obj)
    n02.cleanup(topology)
    check_private(obj)
    (ROOT/'resolv.conf').unlink()
    # Recheck each surviving object immediately before unlinking it.
    if file_identity(ROOT/'control.sock','socket') != obj['socket']: raise Refused('socket changed during cleanup')
    (ROOT/'control.sock').unlink()
    if file_identity(ROOT/'state.json','file') != obj['state_file'] or read_protected(ROOT/'state.json',8192) != obj['state']:
        raise Refused('state changed during cleanup')
    (ROOT/'state.json').unlink()
    # The receipt is written only after all owned resources were removed.
    record_completion(obj['run_id'])


def recover_once(rid):
    valid_id(rid)
    n02 = n02_module(); n02.guard()
    safe_root(ROOT); safe_root(n02.ROOT)
    obj = read_protected(manifest_path(rid), 16384)
    validate_manifest(obj, rid)
    if secure_source(SELF) != obj['helper_sha256']: raise Refused('watchdog version changed')
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip() != obj['boot_id']: raise Refused('boot changed')
    # A receipt is not enough to report success while the ownership lock is busy.
    try:
        fd = n02.acquire_lock(fcntl, timeout=LOCK_TIMEOUT)
    except Exception as exc:
        raise RetryLater('N02 lock unavailable: ' + str(exc)) from exc
    if type(fd) is not int or fd < 0: raise Refused('invalid N02 lock descriptor')
    try:
        if read_protected(manifest_path(rid), 16384) != obj: raise Refused('manifest changed')
        # A completed old run is a no-op even if another run is now active.
        if already_completed(rid):
            print('N01 already completed: ' + rid)
            return
        # A PID that exists, including a reused PID, is ambiguous: never signal it.
        if os.path.exists('/proc/%d' % obj['state']['pid']): raise RetryLater('supervisor PID still exists')
        cleanup_owned(n02, obj)
    finally: os.close(fd)
    print('N01 owned resources recovered: ' + rid)


def recover(rid):
    """Retry only explicitly temporary conditions; never treat exhaustion as success."""
    valid_id(rid)
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return recover_once(rid)
        except RetryLater as exc:
            print('N01 recovery deferred (%d/%d): %s' % (attempt, MAX_ATTEMPTS, exc), file=sys.stderr, flush=True)
            if attempt == MAX_ATTEMPTS:
                raise Refused('recovery attempts exhausted; inspect protected state') from exc
            time.sleep(RETRY_INTERVAL)


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    try:
        if len(sys.argv) != 3 or sys.argv[1] != 'recover': raise Refused('usage: recover RUN_ID')
        recover(sys.argv[2])
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('N01 watchdog refused or failed: '+str(exc), file=sys.stderr); sys.exit(3)
