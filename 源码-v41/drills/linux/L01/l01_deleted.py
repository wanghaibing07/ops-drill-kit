#!/usr/bin/env python3
"""Candidate L01 deleted-open variant, scoped to its own loop image and unit."""
import contextlib
import errno
import io
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

import l01_control as m

m.BASE = m.LAB / 'L01-deleted'
PYTHON = '/usr/bin/python3'
CODE = str(Path(__file__).resolve())
SIZE = 32 * 1024 * 1024
UNIT = re.compile(r'^opsdrill-l01-deleted-[0-9a-f]{24}\.service$')


def expected_unit(rid):
    m.require(isinstance(rid, str) and m.RID.fullmatch(rid), 'BAD_RUN_ID')
    return 'opsdrill-l01-deleted-' + rid + '.service'


def properties(unit):
    m.require(bool(UNIT.fullmatch(unit)), 'BAD_UNIT')
    out = m.command(['systemctl', 'show', unit, '--no-pager',
        '--property=LoadState,ActiveState,ExecStart,FragmentPath,ControlGroup,Type,User,Group,MainPID'])
    result = {}
    for line in out.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            m.require(k not in result, 'DUPLICATE_UNIT_PROPERTY')
            result[k] = v
    return result


def verify_unit(unit, rid, props):
    m.require(unit == expected_unit(rid), 'UNIT_IDENTITY')
    if props.get('LoadState') == 'not-found':
        return False
    raw = props.get('ExecStart', '')
    path = re.search(r'(?:^|[;{]\s*)path=([^ ;]+)\s*;', raw)
    argv = re.search(r'(?:^|[;{]\s*)argv\[\]=(.*?)\s*;\s*ignore_errors=', raw)
    m.require(path is not None and argv is not None, 'UNIT_EXEC_FORMAT')
    args = argv.group(1).strip()
    m.require(not any(c in args for c in '\\"\''), 'UNIT_EXEC_ENCODING')
    m.require(path.group(1) == PYTHON and args.split() == [PYTHON, CODE, 'worker', rid], 'UNIT_EXEC_MISMATCH')
    m.require(props.get('FragmentPath') == '/run/systemd/transient/' + unit, 'UNIT_FRAGMENT')
    m.require(props.get('Type') == 'exec', 'UNIT_TYPE')
    m.require(props.get('User', '') in ('', 'root') and props.get('Group', '') in ('', 'root'), 'UNIT_USER')
    m.require(props.get('ControlGroup', '') in ('', '/system.slice/' + unit), 'UNIT_CGROUP')
    return True


def active(props):
    return props.get('ActiveState') in ('active', 'activating', 'deactivating', 'reloading')


def stop_unit(s):
    unit = s['unit']
    props = properties(unit)
    exists = verify_unit(unit, s['run_id'], props)
    # A timed-out systemd-run may still have a pending submission. When launch
    # was never confirmed, absence alone is not proof that it cannot appear.
    m.require(exists or s.get('phase') != 'MOUNTED', 'UNIT_LAUNCH_UNCONFIRMED')
    if exists and active(props):
        m.command(['systemctl', 'stop', unit], timeout=15)
    props = properties(unit)
    exists = verify_unit(unit, s['run_id'], props)
    m.require(not (exists and active(props)) and not props.get('ControlGroup'), 'UNIT_STILL_ACTIVE')
    if exists and props.get('ActiveState') == 'failed':
        m.command(['systemctl', 'reset-failed', unit], timeout=10)


def state_with_unit(dfd):
    s = m.read_state(dfd)
    m.require(s is not None and s.get('variant') == 'deleted-open', 'BAD_VARIANT')
    m.require(s.get('unit') == expected_unit(s['run_id']), 'BAD_UNIT')
    for k in ('payload_dev', 'payload_ino'):
        m.require(isinstance(s.get(k), int) and s[k] > 0, 'BAD_PAYLOAD_IDENTITY')
    return s


def open_deleted_refs(dev, ino):
    """Conservatively count open descriptors for this inode; never print process data."""
    count = 0
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        path = '/proc/' + name + '/fd'
        try:
            fds = os.listdir(path)
        except FileNotFoundError:
            continue
        except PermissionError:
            raise m.Refused('PROC_FD_INACCESSIBLE')
        for fd in fds:
            try:
                s = os.stat(path + '/' + fd)
            except OSError as exc:
                if exc.errno in (errno.ENOENT, errno.ESRCH):
                    continue
                raise m.Refused('PROC_FD_INACCESSIBLE')
            if s.st_dev == dev and s.st_ino == ino and s.st_nlink == 0:
                count += 1
    return count


def worker(rid):
    m.guard()
    unit = expected_unit(rid)
    with open('/proc/self/cgroup', encoding='ascii') as f:
        m.require(any(x.startswith('0::/') and x.endswith('/' + unit) for x in f.read().splitlines()), 'WORKER_CGROUP')
    dfd = os.open(m.BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        s = state_with_unit(dfd)
        m.require(s['run_id'] == rid and s['phase'] == 'MOUNTED', 'WORKER_STATE')
        run = m.run_path(s)
        _, mount, mounted = m.verify_mount(s, run)
        m.require(mounted, 'MOUNT_MISSING')
        mountfd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open('deleted.log', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=mountfd)
            try:
                st = os.fstat(fd)
                m.require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                          st.st_size == SIZE and (st.st_dev, st.st_ino) == (s['payload_dev'], s['payload_ino']), 'PAYLOAD_CHANGED')
                os.unlink('deleted.log', dir_fd=mountfd)
                while True:
                    time.sleep(60)
            finally:
                os.close(fd)
        finally:
            os.close(mountfd)
    finally:
        os.close(dfd)


def inject(cli_receipt=False):
    # Reuse the inode controller's fully guarded private image setup, then remove
    # only its verified empty files before creating this variant's payload.
    with contextlib.redirect_stdout(io.StringIO()):
        m.inject()
    try:
        with m.locked() as dfd:
            s = m.read_state(dfd)
            m.require(s is not None and s['phase'] == 'FAULT', 'BAD_SETUP')
            run = m.run_path(s)
            _, mount, mounted = m.verify_mount(s, run)
            m.require(mounted, 'MOUNT_MISSING')
            m.check_contents(mount)
            mountfd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for name in os.listdir(mountfd):
                    if m.ENTRY.fullmatch(name):
                        os.unlink(name, dir_fd=mountfd)
                fd = os.open('deleted.log', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=mountfd)
                try:
                    os.posix_fallocate(fd, 0, SIZE)
                    os.fsync(fd)
                    st = os.fstat(fd)
                finally:
                    os.close(fd)
            finally:
                os.close(mountfd)
            s.update(variant='deleted-open', unit=expected_unit(s['run_id']),
                     payload_dev=st.st_dev, payload_ino=st.st_ino, phase='MOUNTED')
            m.write_state(dfd, s)
            m.command(['systemd-run', '--system', '--unit=' + s['unit'], '--service-type=exec',
                '--property=RuntimeMaxSec=1800s', '--property=TimeoutStopSec=5s',
                '--property=KillMode=control-group', '--property=TasksMax=8',
                '--property=MemoryMax=64M', '--property=NoNewPrivileges=yes',
                '--property=UMask=0077', PYTHON, CODE, 'worker', s['run_id']], timeout=15)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                props = properties(s['unit'])
                m.require(verify_unit(s['unit'], s['run_id'], props) and active(props), 'WORKER_NOT_ACTIVE')
                if open_deleted_refs(s['payload_dev'], s['payload_ino']) > 0:
                    m.require(not os.path.lexists(mount / 'deleted.log'), 'PAYLOAD_NOT_UNLINKED')
                    s['phase'] = 'FAULT'
                    m.write_state(dfd, s)
                    result = {'receipt': 'L01_DELETED_OWNER_V1', 'run_id': s['run_id'], 'unit': s['unit']} if cli_receipt else \
                             {'status': 'DELETED_OPEN_PRESENT', 'run_id': s['run_id'], 'unit': s['unit'], 'held_bytes': SIZE}
                    print(json.dumps(result))
                    return 0
                time.sleep(0.1)
            raise m.Refused('WORKER_READY_TIMEOUT')
    except Exception:
        # Preserve unidentified or partly initialized resources for inspection.
        print('L01 deleted-open: incomplete run requires reset or inspection', file=sys.stderr)
        raise


def require_expected(s, rid, unit):
    if rid is not None:
        m.require(s['run_id'] == rid and s['unit'] == unit, 'RUN_ID_MISMATCH')


def check(rid=None, unit=None):
    m.guard()
    with m.locked() as dfd:
        s = state_with_unit(dfd)
        require_expected(s, rid, unit)
        m.require(s['phase'] == 'FAULT', 'INCOMPLETE_RUN')
        run = m.run_path(s)
        _, mount, mounted = m.verify_mount(s, run)
        m.require(mounted, 'MOUNT_MISSING')
        m.check_contents(mount)
        refs = open_deleted_refs(s['payload_dev'], s['payload_ino'])
        if refs:
            print(json.dumps({'status': 'FAULT_PRESENT', 'open_fds': refs}))
            return 1
        v = os.statvfs(mount)
        m.require(v.f_files > 0 and v.f_ffree * 10 >= v.f_files, 'LOW_FREE_INODES')
        m.probe_writable(mount)
        m.verify_logrotate()
        print(json.dumps({'status': 'RECOVERED', 'open_fds': 0}))
        return 0


def clean_named_payload(s):
    """Clean only the recorded payload if launch failed before it was unlinked."""
    run = m.run_path(s)
    _, mount, mounted = m.verify_mount(s, run)
    if not mounted:
        return
    mountfd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fd = os.open('deleted.log', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=mountfd)
        except FileNotFoundError:
            return
        try:
            st = os.fstat(fd)
            m.require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                      st.st_size == SIZE and (st.st_dev, st.st_ino) == (s['payload_dev'], s['payload_ino']),
                      'PAYLOAD_CHANGED')
            path_st = os.stat('deleted.log', dir_fd=mountfd, follow_symlinks=False)
            m.require((path_st.st_dev, path_st.st_ino) == (st.st_dev, st.st_ino), 'PAYLOAD_CHANGED')
            os.unlink('deleted.log', dir_fd=mountfd)
        finally:
            os.close(fd)
    finally:
        os.close(mountfd)


def reset(rid=None, unit=None):
    m.guard()
    if not os.path.lexists(m.BASE):
        m.require(rid is None, 'RUN_ID_MISMATCH')
        print(json.dumps({'status': 'ALREADY_CLEAN'})); return 0
    with m.locked() as dfd:
        s = m.read_state(dfd)
        if s is None:
            m.require(rid is None, 'RUN_ID_MISMATCH')
            m.require(set(os.listdir(m.BASE)) == {m.LOCK}, 'ORPHAN_RESOURCES')
            print(json.dumps({'status': 'ALREADY_CLEAN'})); return 0
        if s.get('variant') == 'deleted-open':
            s = state_with_unit(dfd)
            require_expected(s, rid, unit)
            stop_unit(s)
            m.require(open_deleted_refs(s['payload_dev'], s['payload_ino']) == 0, 'PAYLOAD_STILL_OPEN')
            clean_named_payload(s)
        else:
            m.require(rid is None, 'RUN_ID_MISMATCH')
        m.reset_locked(dfd, s)
        print(json.dumps({'status': 'CLEANUP_PASS', 'run_id': s['run_id']}))
        return 0


def verify_owner(rid, unit):
    m.guard()
    m.require(unit == expected_unit(rid), 'BAD_UNIT')
    with m.locked() as dfd:
        s = state_with_unit(dfd)
        require_expected(s, rid, unit)
        m.require(s['phase'] == 'FAULT', 'INCOMPLETE_RUN')
        run = m.run_path(s)
        _, _, mounted = m.verify_mount(s, run)
        m.require(mounted, 'MOUNT_MISSING')
        verify_unit(unit, rid, properties(unit))
    print(json.dumps({'status': 'OWNER_VERIFIED', 'run_id': rid, 'unit': unit}))
    return 0


def main():
    m.require(len(sys.argv) >= 2, 'USAGE')
    if sys.argv[1] == 'worker':
        m.require(len(sys.argv) == 3, 'USAGE')
        return worker(sys.argv[2])
    if sys.argv[1] == 'inject':
        m.require(len(sys.argv) == 2 or sys.argv[2:] == ['--cli'], 'USAGE')
        return inject(len(sys.argv) == 3)
    if sys.argv[1] == 'verify-owner':
        m.require(len(sys.argv) == 4, 'USAGE')
        return verify_owner(sys.argv[2], sys.argv[3])
    if sys.argv[1] == 'inspect-clean':
        m.require(len(sys.argv) == 2, 'USAGE')
        return m.inspect_clean()
    m.require(sys.argv[1] in ('check', 'reset') and len(sys.argv) in (2, 4), 'USAGE')
    rid, unit = (sys.argv[2], sys.argv[3]) if len(sys.argv) == 4 else (None, None)
    if rid is not None:
        m.require(unit == expected_unit(rid), 'BAD_UNIT')
    return {'check': check, 'reset': reset}[sys.argv[1]](rid, unit)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (m.Refused, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL_CLOSED', 'error': str(exc) if isinstance(exc, m.Refused) else type(exc).__name__}), file=sys.stderr)
        sys.exit(2)
