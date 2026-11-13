"""Candidate M04 lifecycle controller. Run as root inside the dedicated VMware lab.

No primary writes, no SQL import, and no data deletion. State and scratch are
preserved for review. This candidate has not been validated on the VM.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import tempfile
import time

BASE = Path('/var/tmp/opsdrill-m04-controller')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}
RID = re.compile(r'^[0-9a-f]{16}$')
UUID = re.compile(r'^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')
ACTIVE = {'active', 'activating', 'deactivating'}

class SafetyError(RuntimeError):
    pass

def require(value, message):
    if not value:
        raise SafetyError(message)

def run(args, timeout=60):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, env=ENV, check=False)
    require(p.returncode == 0, 'command failed: ' + Path(args[0]).name)
    return p.stdout.decode('utf-8').strip()

def secure_dir(path, create=False):
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077,
            'unsafe controller directory')

def setup():
    require(os.geteuid() == 0, 'root required')
    require(run(['/usr/bin/systemd-detect-virt', '--vm']) == 'vmware', 'VMware required')
    marker = Path('/etc/opsdrill-lab')
    st = marker.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
            and marker.read_text().strip() == 'ops-drill-kit', 'lab marker mismatch')
    secure_dir(BASE, create=True)

def boot_context():
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip().lower()
    require(UUID.fullmatch(boot_id) and hasattr(time, 'CLOCK_BOOTTIME'), 'boot clock unavailable')
    return boot_id, time.clock_gettime(time.CLOCK_BOOTTIME)

def require_same_boot(state):
    boot_id, now = boot_context()
    require(state.get('boot_id') == boot_id and isinstance(state.get('deadline_boottime'), (int, float)),
            'run is from a different boot or lacks a boot deadline')
    return now

def paths(rid, label):
    require(bool(RID.fullmatch(rid)) and label in ('source', 'target'), 'invalid identity')
    root = Path('/var/tmp') / ('opsdrill-m04-run-' + rid) / label
    return root, root / 'data', root / 'run' / 'mysql.sock'

def unit(rid, label):
    paths(rid, label)
    return 'opsdrill-m04-' + label + '-' + rid + '.service'

def init_unit(rid, label):
    return unit(rid, label).removesuffix('.service') + '-init.service'

def init_command(rid, label):
    root, data, _ = paths(rid, label)
    return ['/usr/sbin/mysqld', '--no-defaults', '--initialize-insecure', '--user=mysql',
            '--basedir=/usr', '--datadir=' + str(data), '--log-error=' + str(root / 'init.log')]

def command(rid, label):
    root, data, socket = paths(rid, label)
    args = ['/usr/sbin/mysqld', '--no-defaults', '--user=mysql', '--basedir=/usr',
            '--datadir=' + str(data), '--socket=' + str(socket),
            '--pid-file=' + str(root / 'run/mysql.pid'), '--tmpdir=' + str(root / 'tmp'),
            '--log-error=' + str(root / 'server.log'), '--skip-networking',
            '--performance-schema=OFF', '--innodb-buffer-pool-size=64M', '--max-connections=8']
    return args + (['--log-bin=' + str(data / 'pitr-bin'), '--server-id=211',
                    '--binlog-format=ROW', '--binlog-row-image=FULL'] if label == 'source' else ['--skip-log-bin'])

def properties(name):
    out = run(['/usr/bin/systemctl', 'show', name, '-p', 'LoadState', '-p', 'ActiveState',
               '-p', 'Transient', '-p', 'MainPID', '-p', 'User', '-p', 'RuntimeMaxUSec', '-p', 'ControlGroup'])
    return dict(line.split('=', 1) for line in out.splitlines() if '=' in line)

def owned_process(rid, label, p, initializing=False):
    name = init_unit(rid, label) if initializing else unit(rid, label)
    require(p.get('LoadState') == 'loaded' and p.get('Transient') == 'yes' and
            p.get('User') == 'mysql' and p.get('ControlGroup', '').endswith('/' + name),
            'unit identity mismatch')
    require(p.get('RuntimeMaxUSec') not in (None, '', 'infinity'), 'unit has no runtime limit')
    pid = p.get('MainPID', '')
    require(pid.isdigit() and int(pid) > 1, 'unit has no identifiable process')
    proc = Path('/proc') / pid
    require(proc.stat().st_uid == pwd.getpwnam('mysql').pw_uid, 'process owner mismatch')
    args = (proc / 'cmdline').read_bytes().split(b'\0')
    require(args[-1] == b'', 'invalid process command line')
    args = [x.decode('utf-8') for x in args[:-1]]
    require(args == (init_command(rid, label) if initializing else command(rid, label)), 'process arguments mismatch')
    require((proc / 'exe').resolve() == Path('/usr/sbin/mysqld').resolve(), 'process executable mismatch')

def save(directory, state):
    fd, name = tempfile.mkstemp(prefix='.state-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(state, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, directory / 'state.json')
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def load(directory, rid):
    st = (directory / 'state.json').lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077, 'unsafe state file')
    state = json.loads((directory / 'state.json').read_text(encoding='utf-8'))
    require(state.get('version') == 1 and state.get('run_id') == rid and
            state.get('phase') in ('PREPARING', 'STARTING', 'READY', 'STOPPING', 'STOPPED', 'FAILED'),
            'invalid state')
    return state

def locked(directory):
    fd = os.open(directory / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    st = os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o077, 'unsafe lock')
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd

def sql(rid, label, query):
    socket = paths(rid, label)[2]
    return run(['/usr/bin/mysql', '--no-defaults', '--protocol=SOCKET', '--socket=' + str(socket),
                '--user=root', '--batch', '--skip-column-names', '-e', query], timeout=15)

def verify(rid, label, primary_uuid, expected_uuid=None):
    p = properties(unit(rid, label))
    require(p.get('ActiveState') == 'active', 'instance is not active')
    owned_process(rid, label, p)
    _, data, socket = paths(rid, label)
    fields = sql(rid, label, 'SELECT @@datadir,@@socket,@@skip_networking,@@log_bin,@@server_uuid,@@binlog_format').split('\t')
    require(len(fields) == 6 and Path(fields[0]).resolve() == data.resolve() and fields[1] == str(socket)
            and fields[2] == '1' and fields[3] == ('1' if label == 'source' else '0')
            and UUID.fullmatch(fields[4]) and fields[4].lower() != primary_uuid.lower()
            and (not expected_uuid or fields[4].lower() == expected_uuid.lower())
            and (label != 'source' or fields[5] == 'ROW'), 'database identity mismatch')
    return fields[4]

def absent(p):
    return p.get('LoadState') == 'not-found' and p.get('ActiveState') in ('inactive', 'failed')

def launch(rid, label, initializing, directory, state):
    name = init_unit(rid, label) if initializing else unit(rid, label)
    # Record the intent only after observing that this name does not exist.
    # A concurrent privileged unit creator is outside this controller's trust boundary.
    require(absent(properties(name)), 'unit already exists: ' + name)
    state['attempted'].append(name)
    state['phase'] = 'STARTING'
    save(directory, state)
    if initializing:
        args = ['/usr/bin/systemd-run', '--unit=' + name, '--wait', '--collect', '--service-type=exec',
                '--property=User=mysql', '--property=RuntimeMaxSec=120s', *init_command(rid, label)]
        run(args, timeout=150)
    else:
        run(['/usr/bin/systemd-run', '--unit=' + name, '--service-type=exec',
             '--property=User=mysql', '--property=RuntimeMaxSec=1500s', *command(rid, label)])

def stop_one(rid, label, initializing=False):
    name = init_unit(rid, label) if initializing else unit(rid, label)
    p = properties(name)
    if not absent(p):
        require(p.get('ActiveState') in ACTIVE | {'inactive', 'failed'}, 'unknown unit state')
        if p.get('ActiveState') in ACTIVE:
            owned_process(rid, label, p, initializing)
            run(['/usr/bin/systemctl', 'stop', name])
            p = properties(name)
        require(p.get('ActiveState') in ('inactive', 'failed'), 'unit still active or unknown')
    if not initializing:
        require(not os.path.lexists(paths(rid, label)[2]), 'socket remains; inspect manually')

def reset(rid, directory, state):
    state['phase'] = 'STOPPING'
    save(directory, state)
    errors = []
    if state.get('replay_account') is not None:
        try:
            import m04_replay_account
            m04_replay_account.cleanup_recorded_account(rid, directory, state)
        except Exception as exc:
            errors.append('replay account cleanup: ' + str(exc))
    attempted = state.get('attempted', [])
    valid = {unit(rid, label) for label in ('source', 'target')} | {init_unit(rid, label) for label in ('source', 'target')}
    require(isinstance(attempted, list) and len(attempted) == len(set(attempted)) and set(attempted) <= valid,
            'invalid attempted units')
    for label in ('target', 'source'):
        for initializing in (False, True):
            name = init_unit(rid, label) if initializing else unit(rid, label)
            if name not in attempted:
                continue
            try:
                stop_one(rid, label, initializing)
            except Exception as exc:
                errors.append(name + ': ' + str(exc))
    state['phase'] = 'FAILED' if errors else 'STOPPED'
    save(directory, state)
    require(not errors, '; '.join(errors))

def start(rid, directory, state):
    account = pwd.getpwnam('mysql')
    scratch = paths(rid, 'source')[0].parent
    scratch.mkdir(mode=0o700)
    os.chown(scratch, account.pw_uid, account.pw_gid)
    run(['/usr/bin/chcon', '-t', 'mysqld_db_t', str(scratch)])
    for label in ('source', 'target'):
        root, data, _ = paths(rid, label)
        for path in (root, data, root / 'tmp', root / 'run'):
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
            run(['/usr/bin/chcon', '-t', 'mysqld_var_run_t' if path.name == 'run' else 'mysqld_db_t', str(path)])
        state['current'] = label
        launch(rid, label, True, directory, state)
        launch(rid, label, False, directory, state)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            try:
                identity = verify(rid, label, state['primary_uuid'])
                break
            except (SafetyError, OSError):
                time.sleep(.3)
        else:
            raise SafetyError('instance did not become ready')
        require(identity not in state['uuids'].values(), 'instance UUID collision')
        state['uuids'][label] = identity
        save(directory, state)
    state['phase'] = 'READY'
    save(directory, state)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('start', 'check', 'reset', 'import', 'inject', 'restore', 'check-drill', 'final'))
    parser.add_argument('--run-id')
    args = parser.parse_args()
    setup()
    if args.action == 'start':
        require(args.run_id is None, 'start generates its own run ID')
        rid = secrets.token_hex(8)
        directory = BASE / rid
        directory.mkdir(mode=0o700)
        fd = locked(directory)
        try:
            primary_uuid = run(['/usr/bin/mysql', '--defaults-extra-file=/etc/opsdrill/mysql-admin.cnf',
                                '--batch', '--skip-column-names', '-e', 'SELECT @@server_uuid'])
            require(UUID.fullmatch(primary_uuid), 'invalid primary UUID')
            boot_id, boot_now = boot_context()
            state = {'version': 1, 'run_id': rid, 'phase': 'PREPARING', 'primary_uuid': primary_uuid, 'uuids': {}, 'attempted': [], 'boot_id': boot_id, 'deadline_boottime': boot_now + 1200, 'business_phase': 'NEW'}
            save(directory, state)
            print(json.dumps({'run_id': rid, 'phase': 'PREPARING'}), flush=True)
            try:
                start(rid, directory, state)
            except BaseException:
                try:
                    reset(rid, directory, state)
                except Exception:
                    pass
                raise
            print(json.dumps({'run_id': rid, 'phase': state['phase'], 'business_phase': state.get('business_phase')}))
        finally:
            os.close(fd)
    else:
        require(args.run_id is not None and RID.fullmatch(args.run_id), 'valid --run-id required')
        rid = args.run_id
        directory = BASE / rid
        secure_dir(directory)
        fd = locked(directory)
        try:
            state = load(directory, rid)
            require_same_boot(state)
            if args.action == 'reset':
                reset(rid, directory, state)
            elif args.action in ('import', 'inject', 'restore', 'check-drill', 'final'):
                import m04_business
                operation = {'import': m04_business.import_backup, 'inject': m04_business.inject,
                             'restore': m04_business.restore, 'check-drill': m04_business.check_drill,
                             'final': m04_business.finalize}[args.action]
                m04_business.run_bounded_stage(args.action, operation, rid, directory, state)
            else:
                require(state['phase'] == 'READY' and set(state['uuids']) == {'source', 'target'}, 'run not ready')
                for label in ('source', 'target'):
                    verify(rid, label, state['primary_uuid'], state['uuids'][label])
            print(json.dumps({'run_id': rid, 'phase': state['phase'], 'business_phase': state.get('business_phase')}))
        finally:
            os.close(fd)

if __name__ == '__main__':
    main()


