#!/usr/bin/env python3
"""L03 bounded disk I/O drill. Python 3.9+, systemd 252. No arbitrary paths."""
import contextlib
import fcntl
import hashlib
import mmap
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

LAB = '/mnt/opsdrill'
ROOT = LAB + '/L03'
RUNS = 'runs'
STATE = 'current.json'
LOCK = '.controller.lock'
OWNER_RECEIPT = 'L03_RUN_OWNER_V1'
MARKER = '/etc/opsdrill-lab'
PYTHON = '/usr/bin/python3'
CODE = os.path.realpath(__file__)
RUN_ID = re.compile(r'^[0-9a-f]{24}$')
UNIT_RE = re.compile(r'^opsdrill-l03-([0-9a-f]{24})\.service$')
MIB = 1024 * 1024
WRITE_MIB = 64
READ_PASSES = 4
MAX_SEC = 30
WRITE_CHUNK = 256 * 1024
READ_CHUNK = MIB
OBS_MIN_NS = 2_000_000_000
OBS_MIN_READ = 64 * MIB
OBS_MIN_IOWAIT_PERCENT = 10.0
FREE_MIN = 5 * 1024**3
HEALTH = ('http://127.0.0.1:8080/health', 'http://127.0.0.1:8080/ready')

class Unsafe(RuntimeError):
    pass

def insist(ok, msg):
    if not ok:
        raise Unsafe(msg)

def check_lab():
    insist(os.geteuid() == 0, 'ROOT_REQUIRED')
    with open(MARKER, 'rb') as f:
        insist(f.read().rstrip(b'\n') == b'ops-drill-kit', 'BAD_MARKER')
    cp = subprocess.run(['systemd-detect-virt','--vm'], capture_output=True, text=True, check=False)
    insist(cp.returncode == 0 and cp.stdout.strip() == 'vmware', 'NOT_VMWARE')
    # Require the real mount anchor; must not be a symlink.
    st = os.lstat(LAB)
    insist(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not stat.S_ISLNK(st.st_mode), 'LAB_DIR_UNSAFE')
    insist(os.path.realpath(LAB) == LAB, 'LAB_REALPATH')

def open_dir(path, parent=None):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, dir_fd=parent)
    st = os.fstat(fd)
    insist(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not (st.st_mode & 0o022), 'DIR_PERMISSIONS')
    return fd

def create_root():
    labfd = open_dir(LAB)
    try:
        try:
            os.mkdir('L03', 0o700, dir_fd=labfd)
        except FileExistsError:
            pass
        rootfd = open_dir('L03', labfd)
        insist(stat.S_IMODE(os.fstat(rootfd).st_mode) == 0o700, 'ROOT_MODE')
        try:
            os.mkdir('runs', 0o700, dir_fd=rootfd)
        except FileExistsError:
            pass
        runsfd = open_dir('runs', rootfd)
        insist(stat.S_IMODE(os.fstat(runsfd).st_mode) == 0o700, 'RUNS_MODE')
        return rootfd, runsfd
    finally:
        os.close(labfd)

def existing_root():
    labfd = open_dir(LAB)
    try:
        rootfd = open_dir('L03', labfd)
        insist(stat.S_IMODE(os.fstat(rootfd).st_mode) == 0o700, 'ROOT_MODE')
        runsfd = open_dir('runs', rootfd)
        insist(stat.S_IMODE(os.fstat(runsfd).st_mode) == 0o700, 'RUNS_MODE')
        return rootfd, runsfd
    finally:
        os.close(labfd)

@contextlib.contextmanager
def locked(rootfd):
    fd = os.open(LOCK, os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600, dir_fd=rootfd)
    try:
        st = os.fstat(fd)
        insist(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600, 'LOCK_IDENTITY')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

def read_json(fd, name):
    h = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK, dir_fd=fd)
    try:
        st = os.fstat(h)
        insist(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
               stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= 16384, 'JSON_FILE_IDENTITY')
        return json.loads(os.read(h, 16385))
    finally:
        os.close(h)

def write_all(fd, payload):
    view = memoryview(payload)
    while view:
        n = os.write(fd, view)
        insist(n > 0, 'SHORT_JSON_WRITE')
        view = view[n:]


def atomic_json(fd, name, obj):
    tmp = '.new-' + secrets.token_hex(8)
    h = os.open(tmp, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        payload = (json.dumps(obj, sort_keys=True, separators=(',', ':'))+'\n').encode()
        write_all(h, payload)
        os.fsync(h)
    finally:
        os.close(h)
    os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)


def exclusive_json(fd, name, obj):
    """Create a durable root-owned identity record without replacing anything."""
    h = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        st = os.fstat(h)
        insist(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1,
               'IDENTITY_FILE_UNSAFE')
        payload = (json.dumps(obj, sort_keys=True, separators=(',', ':'))+'\n').encode()
        write_all(h, payload)
        os.fsync(h)
    finally:
        os.close(h)
    os.fsync(fd)

def health():
    for url in HEALTH:
        try:
            with urllib.request.urlopen(url, timeout=2) as res:
                if res.status != 200:
                    return False
        except Exception:
            return False
    return True

def sysctl(*args):
    cp = subprocess.run(['systemctl',*args], capture_output=True, text=True, timeout=10)
    return cp

def unit_properties(unit):
    insist(bool(UNIT_RE.fullmatch(unit)), 'BAD_UNIT_NAME')
    cp = sysctl('show',unit,'--no-pager',
                '--property=LoadState,ActiveState,SubState,ExecStart,FragmentPath,ControlGroup,Type,User,Group,InvocationID,Result,ExecMainCode,ExecMainStatus')
    insist(cp.returncode == 0, 'UNIT_SHOW_FAILED')
    result = {}
    for line in cp.stdout.splitlines():
        if '=' in line:
            k,v = line.split('=',1); result[k] = v
    return result


def parse_execstart(raw):
    """Parse systemd's serialized ExecStart for our whitespace-free argv."""
    path_match = re.search(r'(?:^|[;{]\s*)path=([^ ;]+)\s*;', raw)
    argv_match = re.search(r'(?:^|[;{]\s*)argv\[\]=(.*?)\s*;\s*ignore_errors=', raw)
    insist(path_match is not None and argv_match is not None, 'UNIT_EXEC_SERIALIZATION')
    path = path_match.group(1)
    argv_text = argv_match.group(1).strip()
    insist(bool(argv_text), 'UNIT_EXEC_ARGV_EMPTY')
    # Our arguments contain no spaces, quoting, or escaping. Reject ambiguity.
    insist('\\' not in argv_text and '"' not in argv_text and "'" not in argv_text,
           'UNIT_EXEC_ARGV_ENCODING')
    return path, argv_text.split()


def expected_argv(run_id):
    return [PYTHON, CODE, 'worker', run_id]


def verify_unit(unit, run_id, props):
    insist(unit == 'opsdrill-l03-'+run_id+'.service' and RUN_ID.fullmatch(run_id), 'UNIT_IDENTITY')
    if props.get('LoadState') == 'not-found':
        return False
    path, argv = parse_execstart(props.get('ExecStart',''))
    insist(path == PYTHON and argv == expected_argv(run_id), 'UNIT_EXEC_MISMATCH')
    insist(props.get('FragmentPath') == '/run/systemd/transient/'+unit, 'UNIT_FRAGMENT_MISMATCH')
    insist(props.get('Type') == 'exec', 'UNIT_TYPE_MISMATCH')
    insist(props.get('User','') in ('', 'root'), 'UNIT_USER_MISMATCH')
    insist(props.get('Group','') in ('', 'root'), 'UNIT_GROUP_MISMATCH')
    cg = props.get('ControlGroup','')
    insist(not cg or cg == '/system.slice/'+unit, 'UNIT_CGROUP_MISMATCH')
    invocation = props.get('InvocationID','')
    insist(not invocation or re.fullmatch(r'[0-9a-f]{32}', invocation), 'UNIT_INVOCATION_ID')
    return True

def active(props):
    return props.get('ActiveState') in ('active','activating','deactivating','reloading')


def clear_failed_unit(unit, rid, props):
    """Forget only this verified, stopped transient unit's failed status."""
    insist(verify_unit(unit,rid,props), 'UNIT_NOT_FOUND')
    insist(props.get('ActiveState') == 'failed', 'UNIT_NOT_FAILED')
    insist(not props.get('ControlGroup'), 'UNIT_CGROUP_BUSY')
    cp=sysctl('reset-failed',unit)
    insist(cp.returncode==0, 'UNIT_RESET_FAILED')
    after=unit_properties(unit)
    exists=verify_unit(unit,rid,after)
    insist(not (exists and active(after)), 'UNIT_STILL_RUNNING')
    insist(not after.get('ControlGroup'), 'UNIT_CGROUP_BUSY')


def state_valid(s, rootfd, runsfd):
    insist(isinstance(s,dict) and s.get('version') in (1,2), 'STATE_VERSION')
    rid=s.get('run_id'); insist(isinstance(rid,str) and bool(RUN_ID.fullmatch(rid)), 'STATE_RUN_ID')
    insist(s.get('unit')=='opsdrill-l03-'+rid+'.service', 'STATE_UNIT')
    insist(s.get('status') in ('START_REQUESTED','START_FAILED','STARTED'), 'STATE_STATUS')
    if s.get('version') == 2:
        insist(s.get('exec_argv') == expected_argv(rid), 'STATE_EXEC_ARGV')
    st=os.fstat(rootfd)
    insist(s.get('root_dev')==st.st_dev and s.get('root_ino')==st.st_ino, 'ROOT_REPLACED')
    rfd=open_dir(rid, runsfd)
    try:
        rst=os.fstat(rfd)
        insist(s.get('run_dev')==rst.st_dev and s.get('run_ino')==rst.st_ino, 'RUN_REPLACED')
        insist(stat.S_IMODE(rst.st_mode)==0o700, 'RUN_MODE')
    finally:
        os.close(rfd)
    return rid

def runfd(runsfd, rid):
    insist(bool(RUN_ID.fullmatch(rid)), 'RUN_ID_INVALID')
    return open_dir(rid, runsfd)

def safe_unlink(fd, name, expected=None):
    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    insist(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
           stat.S_IMODE(st.st_mode)==0o600, 'FILE_UNSAFE_'+name)
    if name == 'payload.bin':
        insist(expected is not None, 'PAYLOAD_IDENTITY_REQUIRED')
    if expected is not None:
        insist((st.st_dev,st.st_ino)==tuple(expected), 'FILE_REPLACED_'+name)
    os.unlink(name, dir_fd=fd)


def validate_payload_identity(identity, rid, rootfd, dfd, payload_stat):
    insist(isinstance(identity, dict) and identity.get('version') == 1, 'PAYLOAD_IDENTITY_VERSION')
    insist(identity.get('run_id') == rid, 'PAYLOAD_IDENTITY_RUN_ID')
    rootst = os.fstat(rootfd); runst = os.fstat(dfd)
    insist(identity.get('root_dev') == rootst.st_dev and identity.get('root_ino') == rootst.st_ino,
           'PAYLOAD_IDENTITY_ROOT')
    insist(identity.get('run_dev') == runst.st_dev and identity.get('run_ino') == runst.st_ino,
           'PAYLOAD_IDENTITY_RUN_DIR')
    expected = [identity.get('payload_dev'), identity.get('payload_ino')]
    insist(all(isinstance(x, int) and x > 0 for x in expected), 'PAYLOAD_IDENTITY_FIELDS')
    insist((payload_stat.st_dev, payload_stat.st_ino) == tuple(expected), 'PAYLOAD_IDENTITY_MISMATCH')
    insist(stat.S_ISREG(payload_stat.st_mode) and payload_stat.st_uid == 0 and payload_stat.st_nlink == 1,
           'PAYLOAD_IDENTITY_FILE_TYPE')
    insist(payload_stat.st_size <= WRITE_MIB*MIB, 'PAYLOAD_SIZE_OR_TYPE')
    return expected


def cleanup_run_files(rootfd, dfd, rid, result):
    """Delete only files whose identity is independently recorded."""
    names = set(os.listdir(dfd))
    allowed = {'payload.bin', 'payload.identity.json', 'result.json'}
    insist(names <= allowed, 'UNKNOWN_RUN_FILES')
    payload_exists = 'payload.bin' in names
    identity_exists = 'payload.identity.json' in names
    if payload_exists:
        insist(identity_exists, 'PAYLOAD_IDENTITY_MISSING')
    if identity_exists:
        insist(payload_exists, 'PAYLOAD_MISSING_WITH_IDENTITY')

    expected = None
    if payload_exists:
        identity = read_json(dfd, 'payload.identity.json')
        payload_stat = os.stat('payload.bin', dir_fd=dfd, follow_symlinks=False)
        expected = validate_payload_identity(identity, rid, rootfd, dfd, payload_stat)
        if result is not None:
            insist(isinstance(result, dict) and result.get('payload_identity') == expected,
                   'RESULT_PAYLOAD_IDENTITY_MISMATCH')
    elif result is not None:
        insist(isinstance(result, dict) and result.get('payload_identity') is None,
               'RESULT_PAYLOAD_MISSING')

    # All checks precede the first unlink. A missing result.json is allowed only
    # when payload.identity.json independently proves the payload inode.
    if payload_exists:
        safe_unlink(dfd, 'payload.bin', expected)
        safe_unlink(dfd, 'payload.identity.json')
    if 'result.json' in names:
        safe_unlink(dfd, 'result.json')
    insist(os.listdir(dfd) == [], 'RUN_NOT_EMPTY')

def baseline():
    insist(shutil.disk_usage(LAB).free >= FREE_MIN, 'FREE_SPACE_LOW')
    insist(health(), 'HEALTH_PRECHECK_FAILED')
    for svc in ('mysqld','nginx','orderguard-api'):
        insist(sysctl('is-active',svc).stdout.strip()=='active','SERVICE_NOT_ACTIVE_'+svc)

def new_run():
    check_lab()
    rfd, runsfd = create_root()
    try:
        with locked(rfd):
            try:
                old = read_json(rfd,STATE)
            except FileNotFoundError:
                old = None
            insist(old is None, 'PREVIOUS_RUN_NEEDS_RESET')
            insist(not os.listdir(runsfd), 'ORPHAN_RUNS_NEED_INSPECTION')
            baseline()
            rid=secrets.token_hex(12)
            os.mkdir(rid,0o700,dir_fd=runsfd)
            dfd=runfd(runsfd,rid)
            try:
                st=os.fstat(dfd); rootst=os.fstat(rfd)
                state={'version':2,'run_id':rid,'unit':'opsdrill-l03-'+rid+'.service',
                       'root_dev':rootst.st_dev,'root_ino':rootst.st_ino,
                       'run_dev':st.st_dev,'run_ino':st.st_ino,
                       'exec_argv':expected_argv(rid),
                       'created_wall_ns':time.time_ns(),'status':'START_REQUESTED'}
                atomic_json(rfd,STATE,state)
                # Ownership receipt is emitted only after current.json is durable.
                # Fasttrack must verify it against current.json before any reset.
                print(json.dumps({'receipt':OWNER_RECEIPT,'run_id':rid,'unit':state['unit']}), flush=True)
                cmd=['systemd-run','--system','--unit='+state['unit'],'--service-type=exec',
                     '--property=RuntimeMaxSec=30s','--property=TimeoutStopSec=5s',
                     '--property=KillMode=control-group','--property=TasksMax=16',
                     '--property=MemoryMax=128M','--property=Nice=10',
                     '--property=IOSchedulingClass=idle','--property=NoNewPrivileges=yes',
                     '--property=IOAccounting=yes','--property=IOReadBandwidthMax=/mnt/opsdrill 32M',
                     '--property=UMask=0077',
                     PYTHON,CODE,'worker',rid]
                cp=subprocess.run(cmd,text=True,capture_output=True,timeout=15)
                if cp.returncode:
                    state['status']='START_FAILED'
                    state['launch_error']='systemd-run returned nonzero (details in local journal)'
                    atomic_json(rfd,STATE,state)
                    raise Unsafe('UNIT_START_FAILED: '+cp.stderr.strip()[:300])
                # Verify before returning, but a very short successful run may already be unloaded.
                props=unit_properties(state['unit'])
                exists=verify_unit(state['unit'],rid,props)
                insist(exists or os.path.exists(ROOT+'/runs/'+rid+'/result.json'), 'UNIT_MISSING_AFTER_LAUNCH')
                state['status']='STARTED'
                atomic_json(rfd,STATE,state)
            finally:
                os.close(dfd)
    finally:
        os.close(runsfd); os.close(rfd)

def cpu_counters(text):
    """Aggregate CPU ticks; exclude guest fields already included in user/nice."""
    line = next((x for x in text.splitlines() if x.startswith('cpu ')), None)
    insist(line is not None, 'CPU_STAT_MISSING')
    fields = line.split()[1:]
    insist(len(fields) >= 5, 'CPU_STAT_SHORT')
    ticks = [int(x) for x in fields[:8]]
    insist(all(x >= 0 for x in ticks), 'CPU_STAT_NEGATIVE')
    return sum(ticks), ticks[4]


def proc_cpu():
    with open('/proc/stat', encoding='ascii') as f:
        return cpu_counters(f.read())


def proc_read_bytes():
    with open('/proc/self/io', encoding='ascii') as f:
        values = dict(line.split(':', 1) for line in f if ':' in line)
    value = int(values['read_bytes'].strip())
    insist(value >= 0, 'READ_COUNTER_NEGATIVE')
    return value


def observation(before_cpu, after_cpu, before_read, after_read, elapsed_ns, status, healthy):
    """Observation only: aggregate iowait cannot establish causality."""
    out = {'verdict':'INCONCLUSIVE', 'scope':'system_iowait_not_attributed',
           'elapsed_ns':elapsed_ns, 'storage_read_bytes':None, 'iowait_percent':None}
    if None in (before_cpu, after_cpu, before_read, after_read):
        out['reason'] = 'METRICS_UNAVAILABLE'
        return out
    total = after_cpu[0] - before_cpu[0]
    wait = after_cpu[1] - before_cpu[1]
    reads = after_read - before_read
    if total <= 0 or wait < 0 or wait > total or reads < 0:
        out['reason'] = 'COUNTER_INVALID'
        return out
    out['storage_read_bytes'] = reads
    out['iowait_percent'] = round(100.0 * wait / total, 2)
    if status != 'COMPLETED' or not healthy:
        out['reason'] = 'WORKLOAD_OR_HEALTH_FAILED'
    elif elapsed_ns < OBS_MIN_NS:
        out['reason'] = 'WINDOW_TOO_SHORT'
    elif reads < OBS_MIN_READ:
        out['reason'] = 'STORAGE_READ_TOO_LOW'
    elif 100.0 * wait / total < OBS_MIN_IOWAIT_PERCENT:
        out['verdict'] = 'IOWAIT_THRESHOLD_NOT_MET'
        out['reason'] = 'SYSTEM_IOWAIT_BELOW_THRESHOLD'
    else:
        out['verdict'] = 'SYSTEM_IOWAIT_OBSERVED'
        out['reason'] = 'CORRELATION_REQUIRES_DEVICE_AND_BASELINE_EVIDENCE'
    return out


def optional_metric(reader):
    try:
        return reader()
    except (OSError, ValueError, KeyError, Unsafe):
        return None


def write_payload(fd, deadline, check_health):
    """Write exactly the bounded payload, accounting for partial writes."""
    for offset in range(0, WRITE_MIB*MIB, WRITE_CHUNK):
        deadline()
        if offset % MIB == 0:
            check_health()
        block = hashlib.shake_256(b'opsdrill-l03-v1:' + offset.to_bytes(8, 'little')).digest(WRITE_CHUNK)
        view = memoryview(block)
        while view:
            n = os.write(fd, view)
            insist(0 < n <= len(view), 'SHORT_WRITE')
            view = view[n:]
            yield n


def direct_read_pass(fd, buffer, deadline, check_health):
    """Read precisely one file pass; direct I/O never silently falls back here."""
    os.lseek(fd, 0, os.SEEK_SET)
    read_bytes = 0
    while read_bytes < WRITE_MIB*MIB:
        deadline()
        if read_bytes % (4*MIB) == 0:
            check_health()
        n = os.readv(fd, [buffer])
        if n > 0:
            read_bytes += n
            yield n
        insist(n == READ_CHUNK, 'DIRECT_READ_SHORT')


def block_ancestors(device, seen=None):
    seen=set() if seen is None else seen
    insist(re.fullmatch(r'[0-9]+:[0-9]+', device) is not None, 'IO_DEVICE_FORMAT')
    if device in seen: return seen
    seen.add(device)
    path=(Path('/sys/dev/block')/device).resolve(strict=True)
    if (path/'slaves').is_dir():
        for child in (path/'slaves').iterdir():
            block_ancestors((child/'dev').read_text(encoding='ascii').strip(),seen)
    if (path/'partition').exists():
        block_ancestors((path.parent/'dev').read_text(encoding='ascii').strip(),seen)
    return seen


def capture_bounded_io(rid):
    unit='opsdrill-l03-'+rid+'.service'
    entries=Path('/proc/self/cgroup').read_text(encoding='ascii').splitlines()
    group='0::/system.slice/'+unit
    insist(group in entries, 'IO_CGROUP_IDENTITY')
    cgroup=Path('/sys/fs/cgroup/system.slice')/unit
    limit=[]
    for line in (cgroup/'io.max').read_text(encoding='ascii').splitlines():
        pieces=line.split()
        if pieces and 'rbps=32000000' in pieces[1:]: limit.append(pieces[0])
    insist(len(limit)==1, 'IO_LIMIT_MISSING')
    dev=os.stat(LAB).st_dev;device=str(os.major(dev))+':'+str(os.minor(dev))
    insist(limit[0] in block_ancestors(device), 'IO_LIMIT_DEVICE_MISMATCH')
    fields=device.split(':');lines=[x.split() for x in Path('/proc/diskstats').read_text(encoding='ascii').splitlines()]
    rows=[x for x in lines if x[:2]==fields]
    insist(len(rows)==1 and len(rows[0])>=14, 'IO_DISKSTATS_MISSING')
    records=[x.split() for x in (cgroup/'io.stat').read_text(encoding='ascii').splitlines()]
    matching=[x for x in records if x and x[0]==limit[0]]
    insist(len(matching)<=1, 'IO_CGROUP_DUPLICATE')
    counters=dict(x.split('=',1) for x in matching[0][1:]) if matching else {}
    return {'device':device,'limit_device':limit[0],'unit':unit,'limit_bps':32000000,
            'disk_read_sectors':int(rows[0][5]),'cgroup_read_bytes':int(counters.get('rbytes','0')),
            'monotonic_ns':time.monotonic_ns()}


def validate_bounded_io(before, after, *, run_id, elapsed_ns, application_read_bytes,
             storage_read_bytes, health_before, health_after):
    """Return PASS only for complete same-device, same-cgroup bounded evidence.

    Hardware condition and attribution of host-wide iowait are outside scope.
    """
    import re
    if not isinstance(run_id,str) or not re.fullmatch(r'[0-9a-f]{24}',run_id):return False
    if not isinstance(before,dict) or not isinstance(after,dict):return False
    keys={'device','limit_device','unit','limit_bps','disk_read_sectors','cgroup_read_bytes','monotonic_ns'}
    if set(before)!=keys or set(after)!=keys:return False
    if before['device']!=after['device'] or before['limit_device']!=after['limit_device']:return False
    if before['unit']!=after['unit'] or before['unit']!='opsdrill-l03-'+run_id+'.service':return False
    if before['limit_bps']!=32000000 or after['limit_bps']!=32000000:return False
    for sample in (before,after):
        if not isinstance(sample['device'],str) or not re.fullmatch(r'[0-9]+:[0-9]+',sample['device']):return False
        if not isinstance(sample['limit_device'],str) or not re.fullmatch(r'[0-9]+:[0-9]+',sample['limit_device']):return False
        if any(type(sample[k]) is not int or sample[k]<0 for k in ('disk_read_sectors','cgroup_read_bytes','monotonic_ns','limit_bps')):return False
    if type(elapsed_ns) is not int or not 0<elapsed_ns<=30000000000:return False
    if type(application_read_bytes) is not int or application_read_bytes!=268435456:return False
    if type(storage_read_bytes) is not int or storage_read_bytes<67108864:return False
    if health_before is not True or health_after is not True:return False
    if not 0<after['monotonic_ns']-before['monotonic_ns']<=30000000000:return False
    if after['disk_read_sectors']<=before['disk_read_sectors']:return False
    if after['cgroup_read_bytes']<=before['cgroup_read_bytes']:return False
    return True


def worker(rid):
    check_lab()
    insist(bool(RUN_ID.fullmatch(rid)), 'RUN_ID')
    expected_cgroup='opsdrill-l03-'+rid+'.service'
    with open('/proc/self/cgroup', 'r', encoding='ascii') as cgfile:
        entries=cgfile.read().splitlines()
    insist(any(line.startswith('0::/') and line.endswith('/'+expected_cgroup) for line in entries),
           'WORKER_NOT_IN_OWN_SYSTEMD_UNIT')
    rootfd,runsfd=existing_root()
    dfd=runfd(runsfd,rid)
    born=time.monotonic_ns(); written=0; read_bytes=0; payload_ino=None
    stop={'signal':None}
    def onterm(sig,_frame):
        stop['signal']=sig
        raise InterruptedError('SIGNAL_'+str(sig))
    signal.signal(signal.SIGTERM,onterm)
    signal.signal(signal.SIGINT,onterm)
    result={'status':'FAILED','write_bytes':0,'read_bytes':0,'elapsed_ns':0,'health_ok':False}
    cpu_before = read_before = io_before = None
    try:
        s=read_json(rootfd,STATE)
        insist(state_valid(s,rootfd,runsfd)==rid, 'WORKER_STATE_MISMATCH')
        insist(health(),'WORKER_HEALTH_PRECHECK')
        insist(os.listdir(dfd) == [], 'RUN_DIR_NOT_EMPTY')
        cpu_before = optional_metric(proc_cpu)
        read_before = optional_metric(proc_read_bytes)
        io_before = optional_metric(lambda: capture_bounded_io(rid))
        f=os.open('payload.bin',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_DSYNC,0o600,dir_fd=dfd)
        try:
            st=os.fstat(f); insist(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1,'PAYLOAD_IDENTITY')
            payload_ino=[st.st_dev,st.st_ino]
            rootst=os.fstat(rootfd); runst=os.fstat(dfd)
            identity={'version':1,'run_id':rid,'root_dev':rootst.st_dev,'root_ino':rootst.st_ino,
                      'run_dev':runst.st_dev,'run_ino':runst.st_ino,
                      'payload_dev':st.st_dev,'payload_ino':st.st_ino}
            # Crash before this durable record leaves an orphan reset must preserve.
            exclusive_json(dfd,'payload.identity.json',identity)
            def deadline():
                insist(time.monotonic_ns()-born < 25_000_000_000,'WORKER_DEADLINE')
            def write_health():
                insist(health(),'HEALTH_DURING_WRITE')
            for n in write_payload(f, deadline, write_health):
                written += n
            os.fsync(f)
        finally:
            os.close(f)
        insist(hasattr(os, 'O_DIRECT'), 'DIRECT_IO_UNAVAILABLE')
        rf=os.open('payload.bin',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_DIRECT,dir_fd=dfd)
        try:
            st=os.fstat(rf)
            insist([st.st_dev,st.st_ino]==payload_ino and st.st_size==WRITE_MIB*MIB,'PAYLOAD_CHANGED')
            # Anonymous mmap is page aligned and unrelated to the payload file.
            # Unsupported or stricter alignment fails closed; no buffered fallback.
            with mmap.mmap(-1, READ_CHUNK) as buf:
                def deadline():
                    insist(time.monotonic_ns()-born < 25_000_000_000,'WORKER_DEADLINE')
                def read_health():
                    insist(health(),'HEALTH_DURING_READ')
                for _ in range(READ_PASSES):
                    for n in direct_read_pass(rf, buf, deadline, read_health):
                        read_bytes += n
        finally:
            os.close(rf)
        insist(written==WRITE_MIB*MIB and read_bytes==WRITE_MIB*READ_PASSES*MIB,'BYTE_BUDGET')
        result['status']='COMPLETED'; result['health_ok']=health()
        insist(result['health_ok'],'POST_HEALTH_FAILED')
    except Exception as e:
        result['status']='INTERRUPTED' if isinstance(e,InterruptedError) else 'FAILED'
        result['error_code']=str(e) if isinstance(e,Unsafe) else type(e).__name__
    finally:
        elapsed = time.monotonic_ns()-born
        cpu_after = optional_metric(proc_cpu)
        read_after = optional_metric(proc_read_bytes)
        io_after = optional_metric(lambda: capture_bounded_io(rid))
        result.update(write_bytes=written,read_bytes=read_bytes,
                      elapsed_ns=elapsed,payload_identity=payload_ino,
                      finished_wall_ns=time.time_ns(),io_evidence={'before':io_before,'after':io_after},
                      observation=observation(cpu_before,cpu_after,read_before,read_after,
                                              elapsed,result['status'],result['health_ok']))
        try:
            atomic_json(dfd,'result.json',result)
        finally:
            os.close(dfd); os.close(runsfd); os.close(rootfd)
    print(json.dumps(result))
    return 0 if result['status']=='COMPLETED' else 2

def clean_status():
    cp = sysctl('list-units', '--all', '--plain', '--no-legend', 'opsdrill-l03-*.service')
    insist(cp.returncode == 0, 'UNIT_LIST_FAILED')
    insist(not cp.stdout.strip(), 'ORPHAN_UNIT')
    insist(health(), 'HEALTH_CHECK_FAILED')
    print(json.dumps({'status': 'CLEAN', 'unit_active': False, 'health_current': True}))
    return 0


def inspect():
    check_lab()
    try:
        rootfd,runsfd=existing_root()
    except FileNotFoundError:
        insist(not os.path.lexists(ROOT), 'INCOMPLETE_L03_ROOT')
        return clean_status()
    try:
        with locked(rootfd):
            try:
                s=read_json(rootfd,STATE)
            except FileNotFoundError:
                insist(os.listdir(runsfd)==[], 'ORPHAN_RUNS')
                return clean_status()
            rid=state_valid(s,rootfd,runsfd)
            props=unit_properties(s['unit'])
            exists=verify_unit(s['unit'],rid,props)
            dfd=runfd(runsfd,rid)
            try:
                try: result=read_json(dfd,'result.json')
                except FileNotFoundError: result=None
            finally: os.close(dfd)
            service_active=exists and active(props)
            if service_active:
                status='RUNNING'
            elif result is not None:
                status=result.get('status','UNKNOWN')
            else:
                status='INTERRUPTED_OR_START_FAILED'
            healthy=health()
            worker=result if isinstance(result,dict) else {}
            evidence=worker.get('io_evidence')
            observed=worker.get('observation') if isinstance(worker.get('observation'),dict) else {}
            scoped=(status=='COMPLETED' and not service_active and healthy and worker.get('status')=='COMPLETED'
                    and isinstance(evidence,dict) and validate_bounded_io(evidence.get('before'),evidence.get('after'),
                        run_id=rid,elapsed_ns=worker.get('elapsed_ns'),application_read_bytes=worker.get('read_bytes'),
                        storage_read_bytes=observed.get('storage_read_bytes'),health_before=True,health_after=worker.get('health_ok')))
            print(json.dumps({'run_id':rid,'status':status,'unit_active':bool(service_active),
                              'unit_result':props.get('Result','unavailable'),
                              'worker':result,'health_current':healthy,
                              'bounded_io_contract':'PASS' if scoped else 'PARTIAL'}))
            return 0 if status=='COMPLETED' and not service_active and worker.get('health_ok') and healthy else 2
    finally: os.close(runsfd); os.close(rootfd)

def verify_owner(rid, unit):
    check_lab()
    insist(bool(RUN_ID.fullmatch(rid)), 'OWNER_RUN_ID')
    insist(unit == 'opsdrill-l03-'+rid+'.service', 'OWNER_UNIT')
    rootfd, runsfd = existing_root()
    try:
        with locked(rootfd):
            s = read_json(rootfd, STATE)
            actual = state_valid(s, rootfd, runsfd)
            insist(actual == rid and s.get('unit') == unit, 'OWNER_STATE_MISMATCH')
            props = unit_properties(unit)
            verify_unit(unit, rid, props)
            print(json.dumps({'status':'OWNER_VERIFIED','run_id':rid,'unit':unit}))
            return 0
    finally:
        os.close(runsfd); os.close(rootfd)


def reset(expected_run_id=None, expected_unit=None):
    check_lab()
    if expected_run_id is not None:
        insist(bool(RUN_ID.fullmatch(expected_run_id)), 'RESET_RUN_ID')
        insist(expected_unit == 'opsdrill-l03-'+expected_run_id+'.service', 'RESET_UNIT_ARGUMENT')
    try:
        rootfd,runsfd=existing_root()
    except FileNotFoundError:
        print(json.dumps({'status':'ALREADY_CLEAN'})); return 0
    try:
        with locked(rootfd):
            try: s=read_json(rootfd,STATE)
            except FileNotFoundError:
                insist(os.listdir(runsfd)==[], 'ORPHAN_RUNS')
                print(json.dumps({'status':'ALREADY_CLEAN'})); return 0
            rid=state_valid(s,rootfd,runsfd)
            if expected_run_id is not None:
                insist(rid == expected_run_id, 'RESET_RUN_ID_MISMATCH')
                insist(s.get('unit') == expected_unit, 'RESET_UNIT_MISMATCH')
            props=unit_properties(s['unit'])
            exists=verify_unit(s['unit'],rid,props)
            if exists and active(props):
                cp=sysctl('stop',s['unit'])
                insist(cp.returncode==0,'UNIT_STOP_FAILED')
            # Re-query after stop. A loaded unit must still be the exact argv we created.
            props=unit_properties(s['unit'])
            exists=verify_unit(s['unit'],rid,props)
            insist(not (exists and active(props)), 'UNIT_STILL_RUNNING')
            insist(not props.get('ControlGroup'), 'UNIT_CGROUP_BUSY')
            if exists and props.get('ActiveState') == 'failed':
                clear_failed_unit(s['unit'],rid,props)
            dfd=runfd(runsfd,rid)
            try:
                try: result=read_json(dfd,'result.json')
                except FileNotFoundError: result=None
                cleanup_run_files(rootfd, dfd, rid, result)
            finally: os.close(dfd)
            os.rmdir(rid,dir_fd=runsfd)
            safe_unlink(rootfd,STATE)
            print(json.dumps({'status':'CLEANUP_PASS','run_id':rid,
                              'prior_worker_status':result.get('status') if result else None}))
            return 0
    finally: os.close(runsfd); os.close(rootfd)

def main(argv):
    insist(len(argv)>=2,'USAGE: inject|check|reset [run_id unit]|verify-owner run_id unit|worker run_id')
    cmd=argv[1]
    if cmd=='inject' and len(argv)==2: return new_run() or 0
    if cmd=='check' and len(argv)==2: return inspect()
    if cmd=='reset' and len(argv)==2: return reset()
    if cmd=='reset' and len(argv)==4: return reset(argv[2],argv[3])
    if cmd=='verify-owner' and len(argv)==4: return verify_owner(argv[2],argv[3])
    if cmd=='worker' and len(argv)==3: return worker(argv[2])
    raise Unsafe('BAD_ARGS')

if __name__=='__main__':
    try: sys.exit(main(sys.argv))
    except (Unsafe, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        print(json.dumps({'status':'FAIL_CLOSED','error':str(e) if isinstance(e,Unsafe) else type(e).__name__}),file=sys.stderr)
        sys.exit(2)
