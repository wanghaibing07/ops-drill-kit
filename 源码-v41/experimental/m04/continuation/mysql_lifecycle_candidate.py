"""Cross-command synthetic MySQL PITR candidate. Linux lab only.

This is a separate entry point from the tested one-shot. All files and SQL are
fixed by the run ID and existing probe; errors leave state and resources intact.
"""
import argparse
from contextlib import contextmanager
from dataclasses import fields
import json
import os
from pathlib import Path
import re
import shutil
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import m04_controller as ctl
import mysql_synthetic_drill as drill
import mysql_live_identity as live
import mysql_fixture_gate as fixture
import mysql_binlog_gate as binlog
from mysql_reset_gate import InstanceIdentity

VERSION = 'm04-synthetic-lifecycle-v1'
ACCOUNTS = ('import_account', 'replay_account', 'candidate_replay_account')


def require_run_id(rid):
    ctl.require(isinstance(rid, str) and re.fullmatch(r'[0-9a-f]{16}', rid) is not None,
                'invalid run ID')


def save_phase(directory, state, name):
    state['candidate_phase'] = name
    ctl.save(directory, state)


def records_from_state(rid, state):
    values = state.get('candidate_identities')
    ctl.require(isinstance(values, dict) and set(values) == {'source', 'target'}, 'identity records missing')
    records = {}
    names = {f.name for f in fields(InstanceIdentity)}
    for label in ('source', 'target'):
        value = values[label]
        # dataclasses.asdict retains a tuple during start; JSON reloads it as a list.
        ctl.require(isinstance(value, dict) and set(value) == names and isinstance(value['argv'], (list, tuple)),
                    'identity record malformed')
        value = dict(value)
        value['argv'] = tuple(value['argv'])
        record = InstanceIdentity(**value)
        ctl.require(record.run_id == rid and record.label == label and record.boot_id == state['boot_id']
                    and record.server_uuid == state['uuids'][label].lower()
                    and record.primary_uuid == live.SENTINEL, 'identity record does not belong to run')
        live.check(record, record)
        records[label] = record
    ctl.require(records['source'].server_uuid != records['target'].server_uuid, 'instance UUID collision')
    return records


@contextmanager
def guarded(rid, state):
    records = records_from_state(rid, state)
    original = ctl.verify
    def verify(r, label, primary, expected=None):
        return live.guarded_verify(records, state, original, r, label, primary, expected)
    with patch.object(ctl, 'verify', verify):
        yield


def evidence(state):
    ev = state.get('fixture')
    ctl.require(isinstance(ev, dict) and set(ev) == {'baseline', 'before_delete'}, 'fixture evidence missing')
    return fixture.capture_fixture(ev['baseline'], ev['before_delete'])


def positions(state):
    values = [state.get(key) for key in ('backup_start', 'backup_after', 'replay_stop', 'fault_end')]
    ctl.require(all(isinstance(p, list) and len(p) == 2 and isinstance(p[0], str)
                    and re.fullmatch(r'pitr-bin\.[0-9]{6}', p[0]) and type(p[1]) is int and p[1] >= 4
                    for p in values), 'position evidence missing')
    start, after, stop, end = values
    ctl.require(start == after and start[0] == stop[0] == end[0] and start[1] < stop[1] < end[1],
                'position evidence mismatch')
    return start, stop, end


def prepare_fault(rid, state, directory):
    for label in ('source', 'target'):
        drill.probe.verify_observers(rid, state, label)
    drill.probe.query(rid, state, 'source', drill.probe.TABLE_SQL)
    drill.business.verify_schema_contract(rid, state, 'source')
    baseline = drill.rows(rid, state, 'source')
    drill.probe.query(rid, state, 'source', 'FLUSH BINARY LOGS')
    start = drill.probe.position(rid, state)
    state['backup_start'] = start
    save_phase(directory, state, 'BACKING_UP')
    dump = drill.capture_dump(rid, state, directory)
    after = drill.probe.position(rid, state)
    state['backup_after'] = after
    ctl.save(directory, state)
    fd = os.open(dump, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with drill.backup_gate.audited_dump_stream(fd, start, after) as (sealed, receipt):
            state['backup_sha256'] = receipt.sha256
            save_phase(directory, state, 'IMPORTING')
            drill.import_dump(rid, state, directory, sealed)
    finally:
        os.close(fd)
    drill.business.verify_schema_contract(rid, state, 'target')
    ctl.require(drill.rows(rid, state, 'target') == baseline, 'full backup restore mismatch')
    save_phase(directory, state, 'INJECTING')
    drill.probe.query(rid, state, 'source', 'UPDATE orderguard_restore_m04.orders SET amount_cents=101 WHERE id=91001 AND amount_cents=100')
    state['replay_stop'] = drill.probe.position(rid, state)
    before = drill.rows(rid, state, 'source')
    ev = fixture.capture_fixture(baseline, before)
    state['fixture'] = {'baseline': baseline, 'before_delete': before}
    ctl.save(directory, state)
    drill.probe.query(rid, state, 'source', 'DELETE FROM orderguard_restore_m04.orders WHERE id=91002')
    state['fault_end'] = drill.probe.position(rid, state)
    fixture.verify_fault(ev, drill.rows(rid, state, 'source'))
    positions(state)
    drill.probe.query(rid, state, 'source', 'FLUSH BINARY LOGS')
    ctl.require(drill.probe.position(rid, state)[0] != start[0], 'binlog rotation failed')
    drill.probe.query(rid, state, 'target', 'CREATE TABLE orderguard_restore_m04.other_table (id INT PRIMARY KEY);'
                      'INSERT INTO orderguard_restore_m04.other_table VALUES (1)')
    # Bind the closed log at fault establishment, not only at recovery.
    ctl.verify(rid, 'source', state['primary_uuid'], state['uuids']['source'])
    path = ctl.paths(rid, 'source')[1] / start[0]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with binlog.audited_binlog_stream(fd, start[1], state['replay_stop'][1], state['fault_end'][1]) as (_, _, receipt):
            state['binlog_sha256'] = receipt.sha256
    finally:
        os.close(fd)
    save_phase(directory, state, 'FAULT')


def check_data(rid, state):
    positions(state)
    ev = evidence(state)
    fixture.verify_fault(ev, drill.rows(rid, state, 'source'))
    target = drill.rows(rid, state, 'target')
    if state['candidate_phase'] == 'FAULT':
        ctl.require(target == state['fixture']['baseline'], 'target baseline changed')
        return 'FAULT'
    ctl.require(state['candidate_phase'] == 'RECOVERED', 'run is not checkable')
    fixture.verify_restored(ev, target)
    return 'RECOVERED'


def resolve_data(rid, state, directory):
    ctl.require(check_data(rid, state) == 'FAULT', 'fault not established')
    start, stop, end = positions(state)
    save_phase(directory, state, 'RESOLVING')
    ctl.verify(rid, 'source', state['primary_uuid'], state['uuids']['source'])
    fd = os.open(ctl.paths(rid, 'source')[1] / start[0], os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with binlog.audited_binlog_stream(fd, start[1], stop[1], end[1]) as (sealed, data, receipt):
            ctl.require(receipt.sha256 == state.get('binlog_sha256'), 'binlog differs from fault evidence')
            replay = drill.generate_replay(rid, state, directory, sealed, start[1], stop[1])
            drill.restricted_replay(rid, state, directory, start, stop, end, data, replay)
    finally:
        os.close(fd)
    ev = evidence(state)
    fixture.verify_fault(ev, drill.rows(rid, state, 'source'))
    fixture.verify_restored(ev, drill.rows(rid, state, 'target'))
    ctl.require(not any(state.get(k) for k in ACCOUNTS), 'account cleanup unproven')
    save_phase(directory, state, 'RECOVERED')


def inactive(rid, state, label):
    p = ctl.properties(ctl.unit(rid, label))
    ctl.require(ctl.absent(p) or (p.get('LoadState') == 'loaded' and p.get('ActiveState') in ('inactive', 'failed')),
                'stopped unit state unknown')
    if not ctl.absent(p):
        invocation = ctl.run(['/usr/bin/systemctl', 'show', ctl.unit(rid, label), '-p', 'InvocationID'])
        ctl.require(invocation == 'InvocationID=' + state['candidate_identities'][label]['invocation_id'],
                    'stopped unit identity differs')
    ctl.require(not os.path.lexists(ctl.paths(rid, label)[2]), 'stopped instance socket remains')


def reset_bound(rid, state, directory):
    ctl.require(not any(state.get(k) for k in ACCOUNTS), 'account cleanup unproven')
    stopped = state.get('candidate_stopped', [])
    ctl.require(isinstance(stopped, list) and stopped in ([], ['target'], ['target', 'source']),
                'invalid stopped-instance record')
    for label in ('source', 'target'):
        init = ctl.properties(ctl.init_unit(rid, label))
        ctl.require(ctl.absent(init) or (init.get('LoadState') == 'loaded' and init.get('ActiveState') in ('inactive', 'failed')),
                    'initialization unit state unknown')
        if label in stopped:
            inactive(rid, state, label)
        else:
            ctl.verify(rid, label, live.SENTINEL, state['uuids'][label])
    state['phase'] = 'STOPPING'
    save_phase(directory, state, 'RESETTING')
    for label in ('target', 'source'):
        if label in stopped:
            continue
        ctl.verify(rid, label, live.SENTINEL, state['uuids'][label])
        ctl.stop_one(rid, label)
        stopped.append(label)
        state['candidate_stopped'] = stopped
        ctl.save(directory, state)
    state['phase'] = 'STOPPED'
    save_phase(directory, state, 'STOPPED')


def start_run(rid):
    require_run_id(rid)
    ctl.setup()
    ctl.require(shutil.disk_usage(ctl.BASE).free >= 2 * 1024 ** 3, 'insufficient free disk space')
    directory = ctl.BASE / rid
    directory.mkdir(mode=0o700)
    lock = ctl.locked(directory)
    try:
        boot, now = ctl.boot_context()
        state = {'version': 1, 'run_id': rid, 'phase': 'PREPARING', 'primary_uuid': live.SENTINEL,
                 'uuids': {}, 'attempted': [], 'boot_id': boot, 'deadline_boottime': now + 900,
                 'business_phase': 'TEST_ONLY', 'candidate_phase': 'STARTING', 'lifecycle_version': VERSION}
        ctl.save(directory, state)
        try:
            ctl.start(rid, directory, state)
            live.bind(rid, state, directory, ctl.verify)
            with guarded(rid, state):
                prepare_fault(rid, state, directory)
                ctl.require(check_data(rid, state) == 'FAULT', 'fault not verified')
        except BaseException as exc:
            state['candidate_error_type'] = type(exc).__name__
            state['candidate_failed_phase'] = state.get('candidate_phase')
            save_phase(directory, state, 'NEEDS_INSPECTION')
            raise
    finally:
        os.close(lock)
    return {'run_id': rid, 'status': 'FAULT', 'scope': 'isolated_socket_only'}


def existing(action, rid):
    require_run_id(rid)
    ctl.setup()
    directory = ctl.BASE / rid
    ctl.secure_dir(directory)
    lock = ctl.locked(directory)
    try:
        state = ctl.load(directory, rid)
        ctl.require(state.get('lifecycle_version') == VERSION and state.get('business_phase') == 'TEST_ONLY'
                    and state.get('primary_uuid') == live.SENTINEL, 'not a lifecycle candidate run')
        now = ctl.require_same_boot(state)
        phase = state.get('candidate_phase')
        if action != 'reset':
            ctl.require(now <= state['deadline_boottime'], 'run deadline expired; reset or inspect')
            ctl.require(phase in ('FAULT', 'RECOVERED'), 'run not ready for this action')
        else:
            ctl.require(phase in ('FAULT', 'RECOVERED', 'RESOLVING', 'RESETTING', 'STOPPED', 'NEEDS_INSPECTION'),
                        'run is not safely resettable')
        with guarded(rid, state):
            if action == 'check':
                status = check_data(rid, state)
            elif action == 'resolve':
                if phase == 'FAULT':
                    resolve_data(rid, state, directory)
                status = check_data(rid, state)
                ctl.require(status == 'RECOVERED', 'recovery not verified')
            else:
                reset_bound(rid, state, directory)
                status = 'STOPPED'
        return {'run_id': rid, 'status': status, 'scope': 'isolated_socket_only'}
    finally:
        os.close(lock)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('start', 'check', 'resolve', 'reset'))
    parser.add_argument('run_id')
    args = parser.parse_args(argv)
    try:
        result = start_run(args.run_id) if args.action == 'start' else existing(args.action, args.run_id)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 1 if args.action == 'check' and result['status'] == 'FAULT' else 0
    except Exception as exc:
        print(json.dumps({'run_id': args.run_id, 'status': 'UNCONFIRMED', 'error_type': type(exc).__name__},
                         sort_keys=True), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
