"""Live identity binding for the socket-only synthetic candidate (Linux only)."""
from dataclasses import asdict
from pathlib import Path
import os
import pwd
import stat

import m04_controller as ctl
from mysql_reset_gate import InstanceIdentity, verify_reset_identity

SENTINEL = '00000000-0000-0000-0000-000000000000'


def observe(rid, state, label):
    ctl.require(state.get('run_id') == rid and state.get('business_phase') == 'TEST_ONLY'
                and state.get('primary_uuid') == SENTINEL, 'not a synthetic run')
    ctl.require_same_boot(state)
    unit = ctl.unit(rid, label)
    props = ctl.properties(unit)
    ctl.require(props.get('ActiveState') == 'active', 'instance is not active')
    ctl.owned_process(rid, label, props)
    extra = ctl.run(['/usr/bin/systemctl', 'show', unit, '-p', 'InvocationID'])
    ctl.require(extra.startswith('InvocationID=') and '\n' not in extra, 'missing invocation identity')
    pid = int(props['MainPID'])
    proc = Path('/proc') / str(pid)
    raw = (proc / 'stat').read_text(encoding='ascii')
    close = raw.rfind(')')
    ctl.require(close > 0 and raw[:raw.find(' ')] == str(pid), 'invalid process stat')
    fields = raw[close + 2:].split()
    ctl.require(len(fields) > 19 and fields[19].isdigit(), 'invalid process start time')
    socket = ctl.paths(rid, label)[2].lstat()
    ctl.require(stat.S_ISSOCK(socket.st_mode), 'instance socket missing or invalid')
    argv = (proc / 'cmdline').read_bytes().split(b'\0')
    ctl.require(argv[-1] == b'', 'invalid process command line')
    return InstanceIdentity(rid, label, state['boot_id'], state['uuids'][label].lower(), SENTINEL,
                            unit, extra.split('=', 1)[1], pid, int(fields[19]), proc.stat().st_uid,
                            str((proc / 'exe').resolve()), tuple(x.decode('utf-8') for x in argv[:-1]),
                            props.get('ControlGroup', ''), socket.st_dev, socket.st_ino)


def check(record, live):
    verify_reset_identity(record, live, pwd.getpwnam('mysql').pw_uid,
                          str(Path('/usr/sbin/mysqld').resolve()), synthetic_no_primary=True)


def bind(rid, state, directory, verify):
    records = {}
    ctl.require(set(state['uuids']) == {'source', 'target'}, 'both instance identities required')
    for label in ('source', 'target'):
        verify(rid, label, SENTINEL, state['uuids'][label])
        first = observe(rid, state, label)
        verify(rid, label, SENTINEL, state['uuids'][label])
        check(first, observe(rid, state, label))
        records[label] = first
    state['candidate_identities'] = {label: asdict(record) for label, record in records.items()}
    ctl.save(directory, state)
    return records


def guarded_verify(records, state, verify, rid, label, primary_uuid, expected_uuid=None):
    ctl.require(rid == state.get('run_id') and label in records and primary_uuid == SENTINEL
                and expected_uuid == state['uuids'].get(label), 'unbound verification request')
    check(records[label], observe(rid, state, label))
    result = verify(rid, label, primary_uuid, expected_uuid)
    check(records[label], observe(rid, state, label))
    return result


def reset(rid, state, directory):
    """Stop only bound live instances; stop on first ambiguity, preserve files."""
    ctl.require(not any(state.get(k) for k in ('import_account', 'replay_account', 'candidate_replay_account')),
                'account cleanup unproven')
    for label in ('source', 'target'):
        p = ctl.properties(ctl.init_unit(rid, label))
        ctl.require(ctl.absent(p) or p.get('ActiveState') in ('inactive', 'failed'),
                    'initialization unit state requires inspection')
        ctl.verify(rid, label, SENTINEL, state['uuids'][label])
    state['phase'] = 'STOPPING'
    ctl.save(directory, state)
    for label in ('target', 'source'):
        ctl.verify(rid, label, SENTINEL, state['uuids'][label])
        ctl.stop_one(rid, label)
        state.setdefault('candidate_stopped', []).append(label)
        ctl.save(directory, state)
    state['phase'] = 'STOPPED'
    ctl.save(directory, state)
