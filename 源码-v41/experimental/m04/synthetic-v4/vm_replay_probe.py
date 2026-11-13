"""Disposable MySQL replay probe. Candidate only; NOT executed or VM-validated.

Uses two newly initialized, transient, socket-only MySQL instances. Reads only a limited primary baseline; all mutations use isolated sockets. Synthetic row values and a deliberately
NON-SECRET password marker are used only in these instances.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import patch

import m04_controller as ctl
import m04_business as business
import m04_replay_account as accounts
import pitr_audit
import sealed_replay

SCHEMA = 'orderguard_restore_m04'
ID_UPDATE = 91001
ID_DELETE = 91002
TABLE_SQL = '''CREATE DATABASE orderguard_restore_m04 CHARACTER SET utf8mb4;
CREATE TABLE orderguard_restore_m04.orders (
 id BIGINT UNSIGNED NOT NULL PRIMARY KEY, order_no VARCHAR(32) NOT NULL,
 merchant_id INT UNSIGNED NOT NULL, user_id INT UNSIGNED NOT NULL,
 order_status TINYINT UNSIGNED NOT NULL, amount_cents INT UNSIGNED NOT NULL,
 pay_channel VARCHAR(16) NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL
) ENGINE=InnoDB;
INSERT INTO orderguard_restore_m04.orders VALUES
 (91001,'m04-synthetic-a',88,7,1,100,'test','2026-01-02 03:04:05','2026-01-02 03:04:05'),
 (91002,'m04-synthetic-b',88,8,1,200,'test','2026-01-02 03:04:05','2026-01-02 03:04:05');'''
DELETED_ROW = ['91002', '6D30342D73796E7468657469632D62', '88', '8', '1', '200', '74657374',
               '2026-01-02 03:04:05', '2026-01-02 03:04:05']

class ProbeError(RuntimeError):
    pass

def query(rid, state, label, statement):
    ctl.require_same_boot(state)
    ctl.verify(rid, label, state['primary_uuid'], state['uuids'][label])
    return ctl.sql(rid, label, statement)

def position(rid, state):
    row = query(rid, state, 'source', 'SHOW BINARY LOG STATUS').split('\t')
    ctl.require(len(row) >= 2 and re.fullmatch(r'pitr-bin\.\d{6}', row[0]) and row[1].isdigit(), 'bad position')
    return [row[0], int(row[1])]

def primary_baseline():
    args = ['/usr/bin/mysql', '--defaults-extra-file=/etc/opsdrill/mysql-admin.cnf', '--batch',
            '--skip-column-names', '-e', 'SELECT @@server_uuid; '
            'SELECT COUNT(*),COALESCE(SUM(amount_cents),0) FROM orderguard_stage3.orders']
    output = ctl.run(args, timeout=30).splitlines()
    ctl.require(len(output) == 2 and ctl.UUID.fullmatch(output[0]) and
                re.fullmatch(r'\d+\t\d+', output[1]), 'invalid primary baseline')
    count, total = output[1].split('\t')
    return {'uuid': output[0].lower(), 'count': int(count), 'amount_sum': int(total)}

def verify_observers(rid, state, label):
    ctl.verify(rid, label, state['primary_uuid'], state['uuids'][label])
    # Source needs binlogging to construct the synthetic events; target must not.
    required = '0\t0\t1' if label == 'source' else '0\t0\t0'
    values = ctl.sql(rid, label, 'SELECT @@global.general_log,@@global.slow_query_log,@@global.log_bin')
    ctl.require(values == required, 'unexpected logging configuration')
    active = ctl.sql(rid, label, "SELECT PLUGIN_NAME,COALESCE(PLUGIN_LIBRARY,'BUILTIN') "
                     "FROM information_schema.PLUGINS WHERE PLUGIN_TYPE='AUDIT' AND PLUGIN_STATUS='ACTIVE'")
    # This exception is restricted to a non-secret, disposable probe. The normal
    # account module keeps rejecting every active audit plugin.
    observed = {tuple(line.split('\t')) for line in active.splitlines() if line}
    permitted = {('sha2_cache_cleaner', 'BUILTIN'), ('mysqlx_cache_cleaner', 'BUILTIN')}
    ctl.require(observed <= permitted, 'unreviewed audit plugin')
    ctl.require(ctl.sql(rid, label, 'SELECT COUNT(*) FROM mysql.component') == '0', 'installed component')
    return sorted(observed)

def probe_target_verified(rid, state):
    ctl.require_same_boot(state)
    return verify_observers(rid, state, 'target')

def verify_exact_grants(rid, state, name):
    ctl.require(re.fullmatch(r'm04_[0-9a-f]{16}', name), 'invalid account name')
    output = query(rid, state, 'target', "SHOW GRANTS FOR '" + name + "'@'localhost'")
    principal = '`' + name + '`@`localhost`'
    expected = {'GRANT USAGE ON *.* TO ' + principal,
                'GRANT REPLICATION_APPLIER ON *.* TO ' + principal,
                'GRANT UPDATE ON `orderguard_restore_m04`.`orders` TO ' + principal}
    lines = output.splitlines()
    ctl.require(len(lines) == len(expected) and set(lines) == expected, 'unexpected account grants')

def prepare_fixture(rid, state):
    for label in ('source', 'target'):
        verify_observers(rid, state, label)
        query(rid, state, label, TABLE_SQL)
        business.verify_schema_contract(rid, state, label)
    query(rid, state, 'target', 'CREATE TABLE orderguard_restore_m04.other_table (id INT PRIMARY KEY);'
          'INSERT INTO orderguard_restore_m04.other_table VALUES (1);')
    query(rid, state, 'source', 'FLUSH BINARY LOGS')
    start = position(rid, state)
    query(rid, state, 'source', 'UPDATE orderguard_restore_m04.orders SET amount_cents=101 WHERE id=91001;')
    stop = position(rid, state)
    query(rid, state, 'source', 'DELETE FROM orderguard_restore_m04.orders WHERE id=91002;')
    end = position(rid, state)
    ctl.require(start[0] == stop[0] == end[0] and start[1] < stop[1] < end[1], 'bad boundaries')
    query(rid, state, 'source', 'FLUSH BINARY LOGS')
    ctl.require(position(rid, state)[0] != start[0], 'binlog did not rotate')
    return start, stop, end

def load_binlog(rid, state, name):
    ctl.require(re.fullmatch(r'pitr-bin\.\d{6}', name), 'bad binlog name')
    ctl.verify(rid, 'source', state['primary_uuid'], state['uuids']['source'])
    path = ctl.paths(rid, 'source')[1] / name
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        ctl.require(stat.S_ISREG(st.st_mode) and 4 <= st.st_size <= 16 * 1024 * 1024, 'unsafe binlog')
        data = bytearray()
        while len(data) < st.st_size:
            chunk = os.read(fd, min(1048576, st.st_size - len(data)))
            ctl.require(chunk, 'truncated binlog')
            data.extend(chunk)
        ctl.require(not os.read(fd, 1), 'growing binlog')
        return bytes(data)
    finally:
        os.close(fd)

def create_replay(rid, state, directory, start, stop):
    ctl.verify(rid, 'source', state['primary_uuid'], state['uuids']['source'])
    source = ctl.paths(rid, 'source')[1] / start[0]
    args = ['/usr/bin/mysqlbinlog', '--no-defaults', '--verify-binlog-checksum', '--require-row-format',
            '--start-position=' + str(start[1]), '--stop-position=' + str(stop[1]), str(source)]
    path = directory / 'synthetic-replay.sql'
    business.execute_capture(args, path, seconds=45)
    return path

def client(rid, state, account, credential_fd, statement):
    accounts.target_verified(rid, state)
    socket = ctl.paths(rid, 'target')[2]
    os.lseek(credential_fd, 0, os.SEEK_SET)
    args = ['/usr/bin/mysql', '--defaults-extra-file=/proc/self/fd/' + str(credential_fd), '--protocol=SOCKET',
            '--socket=' + str(socket), '--user=' + account, '--binary-mode=1']
    p = subprocess.run(args, input=statement.encode('ascii'), stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, timeout=20, env=ctl.ENV, pass_fds=(credential_fd,))
    return p.returncode, p.stderr

def deny(result):
    code, stderr = result
    ctl.require(code != 0 and re.search(rb'ERROR 1142 \(42000\)', stderr), 'expected table privilege denial')

def exercise(rid, state, directory, start, stop, end, log_bytes, replay):
    ctl.require(state.get('business_phase') == 'TEST_ONLY' and state.get('run_id') == rid,
                'probe requires its isolated test run')
    probe_target_verified(rid, state)
    # This hex value is deliberately non-secret and has the same shape as a
    # normal generated password. Only the account module's local dependency is
    # replaced; name generation still uses the real random generator.
    marker = secrets.token_hex(32)
    def test_token(n):
        ctl.require(n in (8, 32), 'unexpected credential request')
        return marker if n == 32 else secrets.token_hex(n)
    def verified(test_rid, test_state):
        ctl.require(test_rid == rid and test_state is state, 'unexpected probe target')
        return probe_target_verified(test_rid, test_state)
    with patch.object(accounts, 'ACCOUNT_SAFETY_READY', True), \
         patch.object(accounts, 'target_verified', verified), \
         patch.object(accounts, 'secrets', SimpleNamespace(token_hex=test_token)):
        replay_fd = os.open(replay, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with sealed_replay.audited_replay_stream(replay_fd, log_bytes, start[1], stop[1], end[1],
                        pitr_audit.ORDER_BINLOG_CONTRACT, ID_UPDATE, 100, ID_DELETE, DELETED_ROW) as sealed:
                with accounts.replay_account(rid, directory, state) as account:
                    name = account.name
                    verify_exact_grants(rid, state, name)
                    account.apply(sealed, timeout=45)
                    ctl.require(query(rid, state, 'target', 'SELECT amount_cents FROM orderguard_restore_m04.orders WHERE id=91001') == '101',
                                'update not applied')
                    deny(client(rid, state, name, account.fd, statement='DELETE FROM orderguard_restore_m04.orders WHERE id=91002;'))
                    deny(client(rid, state, name, account.fd, statement='UPDATE orderguard_restore_m04.other_table SET id=2 WHERE id=1;'))
                    ctl.require(query(rid, state, 'target', 'SELECT COUNT(*) FROM orderguard_restore_m04.orders WHERE id=91002') == '1',
                                'denied delete changed data')
                    ctl.require(query(rid, state, 'target', 'SELECT COUNT(*) FROM orderguard_restore_m04.other_table WHERE id=1') == '1',
                                'denied other-table update changed data')
                ctl.require(not state.get('replay_account'), 'account cleanup record remains')
                ctl.require(accounts.account_exists(rid, state, name) == '0', 'test account remains')
        finally:
            os.close(replay_fd)
    return marker

def scan_instance_logs(rid, marker):
    root = ctl.paths(rid, 'target')[0]
    paths = [root / 'server.log', root / 'init.log']
    result = {}
    for path in paths:
        ctl.require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024 * 1024,
                    'missing or unsafe log')
        result[path.name] = marker.encode('ascii') in path.read_bytes()
    return result

def main():
    ctl.setup()
    rid = secrets.token_hex(8)
    directory = ctl.BASE / rid
    directory.mkdir(mode=0o700)
    lock = ctl.locked(directory)
    boot, now = ctl.boot_context()
    state = {'version': 1, 'run_id': rid, 'phase': 'PREPARING', 'primary_uuid': None,
             'uuids': {}, 'attempted': [], 'boot_id': boot, 'deadline_boottime': now + 900,
             'business_phase': 'TEST_ONLY'}
    ctl.save(directory, state)
    marker = None
    outcome = 'FAILED'
    def timed_out(signum, frame):
        raise TimeoutError('probe time limit exceeded')
    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, timed_out)
    signal.setitimer(signal.ITIMER_REAL, 840)
    try:
        before = primary_baseline()
        state['primary_uuid'] = before['uuid']
        state['primary_baseline'] = before
        state['probe_phase'] = 'STARTING'
        ctl.save(directory, state)
        ctl.start(rid, directory, state)
        # Only this non-secret probe allows the two built-in cache-cleaner
        # plugins; the ordinary account implementation remains disabled.
        state['probe_audit_plugins'] = {label: verify_observers(rid, state, label)
                                        for label in ('source', 'target')}
        ctl.save(directory, state)
        start, stop, end = prepare_fixture(rid, state)
        data = load_binlog(rid, state, start[0])
        replay = create_replay(rid, state, directory, start, stop)
        marker = exercise(rid, state, directory, start, stop, end, data, replay)
        outcome = 'OPERATIONS_VERIFIED'
        state['probe_phase'] = outcome
        ctl.save(directory, state)
    except BaseException as exc:
        state['probe_phase'] = 'FAILED'
        state['probe_error_type'] = type(exc).__name__
        ctl.save(directory, state)
        raise
    finally:
        # This attempts recorded account cleanup before stopping either instance.
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        try:
            try:
                ctl.reset(rid, directory, state)
            finally:
                if state.get('primary_baseline'):
                    try:
                        after = primary_baseline()
                        state['primary_after'] = after
                        state['primary_baseline_matches'] = after == state['primary_baseline']
                    except Exception as exc:
                        state['primary_baseline_matches'] = False
                        state['primary_after_error_type'] = type(exc).__name__
                    ctl.save(directory, state)
        finally:
            os.close(lock)
    ctl.require(outcome == 'OPERATIONS_VERIFIED' and marker is not None, 'probe failed')
    ctl.require(state.get('primary_baseline_matches') is True, 'primary baseline changed or unavailable')
    log_hits = scan_instance_logs(rid, marker)
    ctl.require(not any(log_hits.values()), 'non-secret test marker found in instance logs')
    result = {'status': 'TEST_VERIFIED', 'run_id': rid, 'instance_logs_contain_test_marker': log_hits,
              'binlog_sha256': hashlib.sha256(data).hexdigest(), 'replay_sha256': business.digest(replay),
              'primary_baseline_matches': True, 'audit_plugins': state['probe_audit_plugins'],
              'scope': 'non-secret synthetic isolated instance; limited primary baseline'}
    with (directory / 'probe-result.json').open('x', encoding='utf-8') as out:
        json.dump(result, out, sort_keys=True)
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    main()
