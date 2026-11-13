#!/usr/bin/env python3
"""Exercise bounded L01 failure rollback on the authorized VM (actor=agent)."""
import errno
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'drills/linux/L01'))
import l01_control as m  # noqa: E402
import l01_deleted as deleted  # noqa: E402


def clean(variant):
    m.BASE = m.LAB / ('L01-deleted' if variant == 'deleted-open' else 'L01')
    m.inspect_clean()


def fail_inode(stage):
    clean('inode')
    original_command, original_open = m.command, m.os.open
    observed = False
    def command(args, timeout=30):
        nonlocal observed
        if args[0] == stage:
            observed = True
            raise m.Refused('SIMULATED_' + stage.upper() + '_FAILURE')
        return original_command(args, timeout=timeout)
    def open_file(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal observed
        if stage == 'files' and str(path).endswith('/inode-0010') and flags & os.O_CREAT:
            observed = True
            raise OSError(errno.EIO, 'simulated private-file creation failure')
        return original_open(path, flags, mode, dir_fd=dir_fd)
    m.command, m.os.open = command, open_file
    try:
        try:
            m.inject()
        except (m.Refused, OSError):
            pass
        else:
            raise RuntimeError('expected simulated failure did not occur')
    finally:
        m.command, m.os.open = original_command, original_open
    if not observed:
        raise RuntimeError('failure injection was not reached')
    clean('inode')
    return {'case': stage, 'rollback': 'PASS'}


def fail_deleted_after_launch():
    clean('deleted-open')
    original = m.command
    launched = False
    def command(args, timeout=30):
        nonlocal launched
        result = original(args, timeout=timeout)
        if args[0] == 'systemd-run':
            launched = True
            raise m.Refused('SIMULATED_AFTER_UNIT_LAUNCH')
        return result
    m.command = command
    try:
        try:
            deleted.inject()
        except m.Refused as exc:
            if str(exc) != 'SIMULATED_AFTER_UNIT_LAUNCH':
                raise
        else:
            raise RuntimeError('expected simulated failure did not occur')
    finally:
        m.command = original
    if not launched:
        raise RuntimeError('owned unit was not launched')
    with m.locked() as dfd:
        state = deleted.state_with_unit(dfd)
        rid, unit = state['run_id'], state['unit']
        deleted.verify_unit(unit, rid, deleted.properties(unit))
    deleted.reset(rid, unit)
    clean('deleted-open')
    return {'case': 'deleted-after-owned-unit-launch', 'owned_reset': 'PASS'}


def main():
    m.guard()
    clean('inode')
    clean('deleted-open')
    before_mounts = subprocess.check_output(['findmnt', '-rn', '-o', 'TARGET,SOURCE'], text=True)
    before_loops = subprocess.check_output(['losetup', '-a'], text=True)
    results = [fail_inode('mkfs.ext4'), fail_inode('mount'), fail_inode('files'), fail_deleted_after_launch()]
    after_mounts = subprocess.check_output(['findmnt', '-rn', '-o', 'TARGET,SOURCE'], text=True)
    after_loops = subprocess.check_output(['losetup', '-a'], text=True)
    if before_mounts != after_mounts or before_loops != after_loops:
        raise RuntimeError('host mount or loop inventory changed')
    evidence = Path(tempfile.mkdtemp(prefix='opsdrill-l01-failures.', dir='/var/tmp'))
    result = {'actor': 'agent', 'result': 'PASS', 'cases': results,
              'host_mount_and_loop_inventories_unchanged': True}
    (evidence / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'result': 'PASS', 'cases': len(results), 'evidence': str(evidence)}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'result': 'FAIL', 'error': str(exc)}), file=sys.stderr)
        sys.exit(2)
