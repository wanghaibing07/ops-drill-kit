"""Executable review candidate for a disposable MySQL PITR run.

Linux lab only; never executed by local tests. No real business data is read.
On failure leave the run record and resources for identity-based inspection.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import m04_controller as ctl
import m04_business as business
import m04_replay_account as accounts
import vm_replay_probe as probe
import mysql_backup_gate as backup_gate
import mysql_binlog_gate as binlog_gate
import mysql_fixture_gate as fixture_gate
import mysql_live_identity as live_identity

SCHEMA = probe.SCHEMA
ZERO_UUID = '00000000-0000-0000-0000-000000000000'
ROW_SQL = ("SELECT id,HEX(order_no),merchant_id,user_id,order_status,amount_cents,HEX(pay_channel),"
           "DATE_FORMAT(created_at,'%Y-%m-%d %H:%i:%s'),DATE_FORMAT(updated_at,'%Y-%m-%d %H:%i:%s') "
           "FROM orderguard_restore_m04.orders ORDER BY id")


def rows(rid, state, label):
    value = probe.query(rid, state, label, ROW_SQL)
    return [line.split('\t') for line in value.splitlines()]


def phase(directory, state, name):
    state['candidate_phase'] = name
    ctl.save(directory, state)


def cap_output():
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (backup_gate.MAX_DUMP, backup_gate.MAX_DUMP))


def capture_dump(rid, state, directory):
    ctl.require_same_boot(state)
    ctl.verify(rid, 'source', state['primary_uuid'], state['uuids']['source'])
    socket = ctl.paths(rid, 'source')[2]
    args = ['/usr/bin/mysqldump', '--no-defaults', '--protocol=SOCKET', '--socket=' + str(socket),
            '--user=root', '--single-transaction', '--source-data=2', '--set-gtid-purged=OFF',
            '--no-tablespaces', '--skip-add-drop-table', '--skip-add-locks', '--skip-disable-keys',
            '--skip-triggers', '--skip-lock-tables', '--skip-set-charset', '--skip-tz-utc',
            '--skip-dump-date', '--column-statistics=0', SCHEMA, 'orders']
    path = directory / 'synthetic-full.sql'
    with path.open('xb') as out:
        result = subprocess.run(args, stdout=out, stderr=subprocess.DEVNULL, timeout=90,
                                env=ctl.ENV, preexec_fn=cap_output, check=False)
        ctl.require(result.returncode == 0, 'synthetic mysqldump failed')
        out.flush()
        os.fsync(out.fileno())
    return path


def import_grants(rid, state, name):
    output = probe.query(rid, state, 'target', "SHOW GRANTS FOR '" + name + "'@'localhost'")
    principal = '`' + name + '`@`localhost`'
    usage = 'GRANT USAGE ON *.* TO ' + principal
    lines = output.splitlines()
    match = re.fullmatch(r'GRANT ([A-Z, ]+) ON `orderguard_restore_m04`\.\* TO ' + re.escape(principal),
                         next((line for line in lines if ' ON `orderguard_restore_m04`.* TO ' in line), ''))
    ctl.require(len(lines) == 2 and usage in lines and match is not None and
                set(match.group(1).split(', ')) == {'CREATE', 'INSERT'}, 'unexpected import grants')


@contextmanager
def import_account(rid, state, directory):
    """Non-secret disposable account scoped to the synthetic target schema."""
    ctl.require(state.get('run_id') == rid and state.get('business_phase') == 'TEST_ONLY',
                'import account requires the current synthetic run')
    name = 'm04_import_' + secrets.token_hex(8)
    marker = secrets.token_hex(32)  # deliberately non-secret test marker
    ctl.require(re.fullmatch(r'm04_import_[0-9a-f]{16}', name), 'invalid import account')
    with patch.object(accounts, 'target_verified', probe.probe_target_verified):
        ctl.require(not state.get('import_account') and accounts.account_exists(rid, state, name) == '0',
                    'import account collision or unfinished account')
        state['import_account'] = {'name': name, 'status': 'CREATE_ATTEMPTED'}
        ctl.save(directory, state)
        fd = None
        try:
            fd = os.memfd_create('m04-test-import', os.MFD_CLOEXEC)
            os.fchmod(fd, 0o600)
            data = ('[client]\npassword=' + marker + '\n').encode('ascii')
            offset = 0
            while offset < len(data):
                n = os.write(fd, data[offset:])
                ctl.require(n > 0, 'credential descriptor write failed')
                offset += n
            accounts.admin_statement(rid, state, "CREATE USER '" + name + "'@'localhost' IDENTIFIED BY '" + marker + "';")
            accounts.admin_statement(rid, state, "GRANT CREATE, INSERT ON `orderguard_restore_m04`.* TO '" + name + "'@'localhost';")
            import_grants(rid, state, name)
            yield name, fd
        finally:
            if fd is not None:
                os.close(fd)
            # A failed DROP or absence check leaves the durable intent intact.
            accounts.admin_statement(rid, state, "DROP USER IF EXISTS '" + name + "'@'localhost';")
            ctl.require(accounts.account_exists(rid, state, name) == '0', 'import account absence unproven')
            state.pop('import_account')
            ctl.save(directory, state)


def import_dump(rid, state, directory, dump_fd):
    probe.probe_target_verified(rid, state)
    # Only a fixed database is created by the existing target-local admin.
    probe.query(rid, state, 'target', 'CREATE DATABASE orderguard_restore_m04 CHARACTER SET utf8mb4')
    with import_account(rid, state, directory) as (name, credential_fd):
        probe.probe_target_verified(rid, state)
        os.lseek(credential_fd, 0, os.SEEK_SET)
        os.lseek(dump_fd, 0, os.SEEK_SET)
        socket = ctl.paths(rid, 'target')[2]
        args = ['/usr/bin/mysql', '--defaults-extra-file=/proc/self/fd/' + str(credential_fd),
                '--protocol=SOCKET', '--socket=' + str(socket), '--user=' + name,
                '--database=' + SCHEMA, '--binary-mode=1']
        result = subprocess.run(args, stdin=dump_fd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=ctl.ENV, pass_fds=(credential_fd,), timeout=90, check=False)
        ctl.require(result.returncode == 0, 'synthetic dump import failed')


def generate_replay(rid, state, directory, binlog_fd, start, stop):
    ctl.verify(rid, 'source', state['primary_uuid'], state['uuids']['source'])
    path = directory / 'synthetic-replay.sql'
    args = ['/usr/bin/mysqlbinlog', '--no-defaults', '--verify-binlog-checksum', '--require-row-format',
            '--start-position=' + str(start), '--stop-position=' + str(stop), '/proc/self/fd/' + str(binlog_fd)]
    os.lseek(binlog_fd, 0, os.SEEK_SET)
    with path.open('xb') as out:
        result = subprocess.run(args, stdout=out, stderr=subprocess.DEVNULL, env=ctl.ENV,
                                pass_fds=(binlog_fd,), timeout=45, preexec_fn=cap_output, check=False)
        ctl.require(result.returncode == 0, 'mysqlbinlog failed')
        out.flush()
        os.fsync(out.fileno())
    return path


def restricted_replay(rid, state, directory, start, stop, end, data, replay):
    # Preserve a second intent until the probe has independently confirmed the
    # account is absent; its existing context manager clears its own record
    # immediately after DROP, before the probe's subsequent absence check.
    original = accounts.account_exists

    def tracked(test_rid, test_state, name):
        ctl.require(test_rid == rid and test_state is state and
                    re.fullmatch(r'm04_[0-9a-f]{16}', name), 'unexpected replay account identity')
        if 'candidate_replay_account' not in state:
            state['candidate_replay_account'] = {'name': name, 'status': 'PROBE_ATTEMPT'}
            ctl.save(directory, state)
        ctl.require(state['candidate_replay_account']['name'] == name, 'replay account changed')
        return original(test_rid, test_state, name)

    ctl.require('candidate_replay_account' not in state, 'prior replay account requires inspection')
    with patch.object(accounts, 'account_exists', tracked):
        probe.exercise(rid, state, directory, start, stop, end, data, replay)
    ctl.require('candidate_replay_account' in state and not state.get('replay_account'),
                'replay account cleanup unproven')
    state.pop('candidate_replay_account')
    ctl.save(directory, state)


def exercise(rid, state, directory):
    ctl.require(state.get('run_id') == rid and state.get('business_phase') == 'TEST_ONLY',
                'exercise requires the current synthetic run')
    for label in ('source', 'target'):
        probe.verify_observers(rid, state, label)
    probe.query(rid, state, 'source', probe.TABLE_SQL)
    business.verify_schema_contract(rid, state, 'source')
    baseline = rows(rid, state, 'source')
    probe.query(rid, state, 'source', 'FLUSH BINARY LOGS')
    start = probe.position(rid, state)
    state['backup_start'] = start
    phase(directory, state, 'BACKING_UP')
    dump = capture_dump(rid, state, directory)
    after_dump = probe.position(rid, state)
    state['backup_after'] = after_dump
    ctl.save(directory, state)
    dump_fd = os.open(dump, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with backup_gate.audited_dump_stream(dump_fd, start, after_dump) as (sealed_dump, receipt):
            state['backup_sha256'] = receipt.sha256
            phase(directory, state, 'IMPORTING')
            import_dump(rid, state, directory, sealed_dump)
    finally:
        os.close(dump_fd)
    business.verify_schema_contract(rid, state, 'target')
    ctl.require(rows(rid, state, 'target') == baseline, 'full backup restore mismatch')
    phase(directory, state, 'INJECTING')
    probe.query(rid, state, 'source', 'UPDATE orderguard_restore_m04.orders SET amount_cents=101 WHERE id=91001 AND amount_cents=100')
    stop = probe.position(rid, state)
    state['replay_stop'] = stop
    ctl.save(directory, state)
    evidence = fixture_gate.capture_fixture(baseline, rows(rid, state, 'source'))
    probe.query(rid, state, 'source', 'DELETE FROM orderguard_restore_m04.orders WHERE id=91002')
    end = probe.position(rid, state)
    state['fault_end'] = end
    ctl.save(directory, state)
    fixture_gate.verify_fault(evidence, rows(rid, state, 'source'))
    ctl.require(start[0] == stop[0] == end[0] and start[1] < stop[1] < end[1], 'invalid boundaries')
    probe.query(rid, state, 'source', 'FLUSH BINARY LOGS')
    ctl.require(probe.position(rid, state)[0] != start[0], 'binlog rotation failed')
    # Restricted replay probe also checks rejection on an unrelated fixed table.
    probe.query(rid, state, 'target', 'CREATE TABLE orderguard_restore_m04.other_table (id INT PRIMARY KEY);'
                'INSERT INTO orderguard_restore_m04.other_table VALUES (1)')
    ctl.verify(rid, 'source', state['primary_uuid'], state['uuids']['source'])
    path = ctl.paths(rid, 'source')[1] / start[0]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with binlog_gate.audited_binlog_stream(fd, start[1], stop[1], end[1]) as (sealed_binlog, data, receipt):
            replay = generate_replay(rid, state, directory, sealed_binlog, start[1], stop[1])
            state['binlog_sha256'] = receipt.sha256
            phase(directory, state, 'REPLAYING')
            restricted_replay(rid, state, directory, start, stop, end, data, replay)
    finally:
        os.close(fd)
    fixture_gate.verify_fault(evidence, rows(rid, state, 'source'))
    fixture_gate.verify_restored(evidence, rows(rid, state, 'target'))
    ctl.require(not state.get('import_account') and not state.get('replay_account') and
                not state.get('candidate_replay_account'), 'account record remains')
    phase(directory, state, 'DATA_VERIFIED')


def main():
    ctl.setup()
    ctl.require(shutil.disk_usage(ctl.BASE).free >= 2 * 1024 ** 3, 'insufficient free disk space')
    rid = secrets.token_hex(8)
    directory = ctl.BASE / rid
    directory.mkdir(mode=0o700)
    lock = ctl.locked(directory)
    boot, now = ctl.boot_context()
    state = {'version': 1, 'run_id': rid, 'phase': 'PREPARING', 'primary_uuid': ZERO_UUID,
             'uuids': {}, 'attempted': [], 'boot_id': boot, 'deadline_boottime': now + 900,
             'business_phase': 'TEST_ONLY', 'candidate_phase': 'PREPARING'}
    ctl.save(directory, state)
    print(json.dumps({'run_id': rid, 'phase': 'PREPARING', 'scope': 'synthetic isolated MySQL candidate'}), flush=True)

    def timed_out(signum, frame):
        raise TimeoutError('candidate time limit exceeded')

    old = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, timed_out)
    signal.setitimer(signal.ITIMER_REAL, 840)
    try:
        phase(directory, state, 'STARTING')
        ctl.start(rid, directory, state)
        ctl.require(len(set(state['uuids'].values())) == 2, 'instance UUID collision')
        original_verify = ctl.verify
        records = live_identity.bind(rid, state, directory, original_verify)
        def guarded(r, label, primary, expected=None):
            return live_identity.guarded_verify(records, state, original_verify, r, label, primary, expected)
        with patch.object(ctl, 'verify', guarded):
            exercise(rid, state, directory)
            phase(directory, state, 'RESETTING')
            live_identity.reset(rid, state, directory)
        phase(directory, state, 'SYNTHETIC_RESET_COMPLETE')
        print(json.dumps({'run_id': rid, 'phase': 'SYNTHETIC_RESET_COMPLETE',
                          'scope': 'synthetic isolated MySQL candidate; no primary verification'}), flush=True)
    except BaseException as exc:
        # Do not guess ownership or automatically remove resources after failure.
        state['candidate_phase'] = 'NEEDS_INSPECTION'
        state['candidate_error_type'] = type(exc).__name__
        try:
            ctl.save(directory, state)
        finally:
            print(json.dumps({'run_id': rid, 'phase': 'NEEDS_INSPECTION',
                              'error_type': type(exc).__name__}), flush=True)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
        os.close(lock)


if __name__ == '__main__':
    main()
