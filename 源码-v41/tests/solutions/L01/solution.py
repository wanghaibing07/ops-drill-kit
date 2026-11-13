#!/usr/bin/env python3
"""Resolve only a verified L01 test run; leave its resources for check/reset."""
import argparse
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'drills/linux/L01'))
import l01_control as m  # noqa: E402
import l01_deleted as deleted  # noqa: E402


def resolve(variant, rid, unit=None):
    m.require(variant in ('inode', 'deleted-open') and m.RID.fullmatch(rid), 'BAD_ARGUMENT')
    if variant == 'deleted-open':
        m.require(unit == deleted.expected_unit(rid), 'BAD_UNIT')
    else:
        m.require(unit is None, 'BAD_UNIT')
    m.BASE = m.LAB / ('L01-deleted' if variant == 'deleted-open' else 'L01')
    m.guard()
    with m.locked() as dfd:
        state = m.read_state(dfd)
        m.require(state is not None and state['run_id'] == rid and state['phase'] == 'FAULT', 'RUN_ID_MISMATCH')
        if variant == 'deleted-open':
            state = deleted.state_with_unit(dfd)
            m.require(state['run_id'] == rid and state['unit'] == unit, 'RUN_ID_MISMATCH')
        else:
            m.require(state.get('variant') != 'deleted-open', 'BAD_VARIANT')
        run = m.run_path(state)
        _, mount, mounted = m.verify_mount(state, run)
        m.require(mounted, 'MOUNT_MISSING')
        m.check_contents(mount)
        if variant == 'deleted-open':
            deleted.verify_unit(unit, rid, deleted.properties(unit))
            m.require(deleted.open_deleted_refs(state['payload_dev'], state['payload_ino']) > 0, 'NO_OWNED_HOLDER')
            deleted.stop_unit(state)
            m.require(deleted.open_deleted_refs(state['payload_dev'], state['payload_ino']) == 0, 'PAYLOAD_STILL_OPEN')
            return {'status': 'MITIGATED', 'variant': variant, 'stopped_unit': unit}

        fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        removed = 0
        try:
            for name in sorted(os.listdir(fd)):
                if not m.ENTRY.fullmatch(name):
                    continue
                entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
                m.require(stat.S_ISREG(entry.st_mode) and entry.st_uid == m.OWNER and
                          entry.st_nlink == 1 and entry.st_size == 0, 'UNKNOWN_MOUNT_CONTENT')
                os.unlink(name, dir_fd=fd)
                removed += 1
                counts = os.statvfs(mount)
                if counts.f_files > 0 and counts.f_ffree * 10 >= counts.f_files:
                    break
        finally:
            os.close(fd)
        counts = os.statvfs(mount)
        m.require(removed > 0 and counts.f_files > 0 and counts.f_ffree * 10 >= counts.f_files,
                  'INSUFFICIENT_INODE_RECOVERY')
        return {'status': 'MITIGATED', 'variant': variant, 'removed_empty_files': removed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('variant', choices=('inode', 'deleted-open'))
    parser.add_argument('run_id')
    parser.add_argument('unit', nargs='?')
    args = parser.parse_args()
    print(json.dumps(resolve(args.variant, args.run_id, args.unit)))


if __name__ == '__main__':
    try:
        main()
    except (m.Refused, OSError, ValueError) as exc:
        print(json.dumps({'status': 'FAIL_CLOSED', 'error': str(exc)}), file=sys.stderr)
        sys.exit(2)
