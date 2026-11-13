"""Review candidate: bounded 1040 probe on a fresh M04 controller run.

Linux/VM execution is explicit and has not been performed for this candidate.
"""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time

MAX_HOLDERS = 12
HOLDER_TTL = 90
PROBE_TTL = 300
MARKER = 'm03_public_test_marker_2026'
ZERO_UUID = '00000000-0000-0000-0000-000000000000'
MYSQL = '/usr/bin/mysql'
TIMEOUT = '/usr/bin/timeout'


def load_controller():
    path = Path(__file__).resolve().parent.parent / 'm04' / 'm04_controller.py'
    spec = importlib.util.spec_from_file_location('m03_m04_controller', path)
    if spec is None or spec.loader is None:
        raise RuntimeError('M04 controller unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def target(ctl, rid, state):
    ctl.require_same_boot(state)
    require(state.get('run_id') == rid and state.get('business_phase') == 'M03_TEST_ONLY'
            and state.get('phase') == 'READY' and set(state.get('uuids', {})) == {'source', 'target'},
            'invalid isolated test run')
    ctl.verify(rid, 'target', state['primary_uuid'], state['uuids']['target'])


def query(ctl, rid, state, sql):
    target(ctl, rid, state)
    return ctl.sql(rid, 'target', sql)


def bounded_limit(value):
    require(value.isascii() and value.isdigit(), 'invalid max_connections')
    count = int(value)
    require(1 <= count <= MAX_HOLDERS, 'isolated max_connections exceeds probe bound')
    return count


def is_1040(result):
    return result.returncode != 0 and bool(re.search(rb'ERROR 1040 \(08004\)', result.stderr))


def client_args(ctl, rid, name, fd):
    socket = ctl.paths(rid, 'target')[2]
    return [MYSQL, '--defaults-extra-file=/proc/self/fd/' + str(fd), '--protocol=SOCKET',
            '--socket=' + str(socket), '--user=' + name, '--connect-timeout=3',
            '--batch', '--skip-column-names']


@contextmanager
def client_option_fd(fd):
    # open(), unlike dup(), creates an independent open-file description and
    # offset. Each child inherits only its own handle to the same memfd.
    child_fd = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_CLOEXEC)
    try:
        yield child_fd
    finally:
        os.close(child_fd)


def one_client(ctl, rid, name, fd):
    with client_option_fd(fd) as client_fd:
        return subprocess.run(client_args(ctl, rid, name, client_fd), input=b'SELECT 1;',
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8,
                              env=ctl.ENV, pass_fds=(client_fd,))


def sleepers(ctl, rid, state, name):
    result = query(ctl, rid, state, "SELECT COUNT(*) FROM information_schema.PROCESSLIST "
                   "WHERE USER='" + name + "' AND COMMAND='Sleep'")
    require(result.isascii() and result.isdigit(), 'invalid processlist count')
    return int(result)


def wait_sleepers(ctl, rid, state, name, expected, timeout=15):
    deadline = time.monotonic() + timeout
    while True:
        value = sleepers(ctl, rid, state, name)
        if value == expected:
            return value
        require(value <= MAX_HOLDERS and time.monotonic() < deadline, 'unexpected or timed-out connection count')
        time.sleep(.2)


def stop_holders(holders):
    errors = []
    for proc in holders:
        try:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
            if proc.stdin is not None:
                proc.stdin.close()
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(type(exc).__name__)
    require(not errors, 'holder cleanup failed: ' + ','.join(errors))


def exercise(ctl, rid, directory, state):
    target(ctl, rid, state)
    count = bounded_limit(query(ctl, rid, state, 'SELECT @@global.max_connections'))
    name = 'm03_' + rid
    require(re.fullmatch(r'm03_[0-9a-f]{16}', name), 'invalid synthetic account')
    exists = "SELECT COUNT(*) FROM mysql.user WHERE User='" + name + "' AND Host='localhost'"
    require(query(ctl, rid, state, exists) == '0', 'synthetic account already exists')
    holders = []
    fd = None
    state['m03_probe'] = {'phase': 'CREATE_ATTEMPTED', 'account': name, 'limit': count}
    ctl.save(directory, state)
    try:
        query(ctl, rid, state, "CREATE USER '" + name + "'@'localhost' IDENTIFIED BY '" + MARKER + "'")
        grants = query(ctl, rid, state, "SHOW GRANTS FOR '" + name + "'@'localhost'").splitlines()
        require(grants == ['GRANT USAGE ON *.* TO `' + name + '`@`localhost`'], 'unexpected account privileges')
        fd = os.memfd_create('m03-nonsecret', os.MFD_CLOEXEC)
        os.fchmod(fd, 0o600)
        data = ('[client]\npassword=' + MARKER + '\n').encode('ascii')
        offset = 0
        while offset < len(data):
            n = os.write(fd, data[offset:])
            require(n > 0, 'credential marker write failed')
            offset += n
        require(one_client(ctl, rid, name, fd).returncode == 0, 'test account cannot connect')
        state['m03_probe']['phase'] = 'INJECTING'
        ctl.save(directory, state)
        for _ in range(count):
            target(ctl, rid, state)
            with client_option_fd(fd) as client_fd:
                args = [TIMEOUT, '--signal=TERM', '--kill-after=5s', str(HOLDER_TTL)] + client_args(ctl, rid, name, client_fd)
                holders.append(subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL, env=ctl.ENV, pass_fds=(client_fd,),
                                                start_new_session=True))
        wait_sleepers(ctl, rid, state, name, count)
        target(ctl, rid, state)
        refusal = one_client(ctl, rid, name, fd)
        require(is_1040(refusal), 'no explicit MySQL 1040; refusing to claim exhaustion')
        state['m03_probe'].update(phase='EXHAUSTION_OBSERVED', sleep_connections=count, error=1040)
        ctl.save(directory, state)
        stop_holders(holders)
        wait_sleepers(ctl, rid, state, name, 0)
        target(ctl, rid, state)
        recovered = one_client(ctl, rid, name, fd)
        require(recovered.returncode == 0 and recovered.stdout.strip() == b'1', 'test account did not recover')
        state['m03_probe']['phase'] = 'RECOVERED'
        ctl.save(directory, state)
    finally:
        try:
            stop_holders(holders)
        finally:
            if fd is not None:
                os.close(fd)
    # On exceptional exit the controller stops the entire disposable instance;
    # the CREATE_ATTEMPTED record remains in the protected run state.
    query(ctl, rid, state, "DROP USER '" + name + "'@'localhost'")
    require(query(ctl, rid, state, exists) == '0', 'synthetic account remains')
    state['m03_probe']['phase'] = 'ACCOUNT_REMOVED'
    ctl.save(directory, state)


def run_probe(ctl):
    ctl.setup()
    rid = secrets.token_hex(8)
    directory = ctl.BASE / rid
    directory.mkdir(mode=0o700)
    lock = ctl.locked(directory)
    boot, now = ctl.boot_context()
    state = {'version': 1, 'run_id': rid, 'phase': 'PREPARING', 'primary_uuid': ZERO_UUID,
             'uuids': {}, 'attempted': [], 'boot_id': boot, 'deadline_boottime': now + 900,
             'business_phase': 'M03_TEST_ONLY', 'm03_probe': {'phase': 'STARTING'}}
    ctl.save(directory, state)
    previous = signal.getsignal(signal.SIGALRM)
    def expired(signum, frame):
        raise TimeoutError('M03 probe deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, PROBE_TTL)
    succeeded = False
    try:
        ctl.start(rid, directory, state)
        exercise(ctl, rid, directory, state)
        succeeded = True
    except BaseException as exc:
        state['m03_error_type'] = type(exc).__name__
        ctl.save(directory, state)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        try:
            ctl.reset(rid, directory, state)
        finally:
            os.close(lock)
    require(succeeded and state['phase'] == 'STOPPED' and
            state['m03_probe']['phase'] == 'ACCOUNT_REMOVED', 'probe or reset incomplete')
    result = {'status': 'ISOLATED_DB_PROBE_PASSED', 'run_id': rid, 'mysql_error': 1040,
              'connections': state['m03_probe']['limit'], 'reset': 'STOPPED',
              'api_readiness': 'NOT_TESTED', 'pool_tests': 'NOT_TESTED', 'overall_drill': 'INCOMPLETE'}
    state['m03_probe']['result'] = result
    ctl.save(directory, state)
    print(json.dumps(result, sort_keys=True))
    return result


def main():
    parser = argparse.ArgumentParser(description='Fresh isolated M03 MySQL probe (candidate)')
    parser.add_argument('--execute-isolated-probe', action='store_true')
    args = parser.parse_args()
    require(args.execute_isolated_probe, 'explicit --execute-isolated-probe required')
    run_probe(load_controller())


if __name__ == '__main__':
    main()
