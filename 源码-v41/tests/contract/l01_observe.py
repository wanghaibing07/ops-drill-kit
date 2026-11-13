#!/usr/bin/env python3
"""Verify L01 fault/recovery observations on the owned private mount."""
import argparse
import errno
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'drills/linux/L01'))
import l01_control as m  # noqa: E402
import l01_deleted as deleted  # noqa: E402


def observe(variant, phase, rid):
    m.require(variant in ('inode', 'deleted-open') and phase in ('fault', 'recovered') and
              m.RID.fullmatch(rid), 'BAD_ARGUMENT')
    m.BASE = m.LAB / ('L01-deleted' if variant == 'deleted-open' else 'L01')
    m.guard()
    with m.locked() as dfd:
        state = m.read_state(dfd)
        m.require(state is not None and state['run_id'] == rid and state['phase'] == 'FAULT', 'RUN_ID_MISMATCH')
        if variant == 'deleted-open':
            state = deleted.state_with_unit(dfd)
            deleted.verify_unit(state['unit'], rid, deleted.properties(state['unit']))
        else:
            m.require(state.get('variant') != 'deleted-open', 'BAD_VARIANT')
        run = m.run_path(state)
        _, mount, mounted = m.verify_mount(state, run)
        m.require(mounted, 'MOUNT_MISSING')
        m.check_contents(mount)
        fs = os.statvfs(mount)
        m.require(fs.f_files > 0 and fs.f_frsize > 0, 'INVALID_FILESYSTEM')
        info = {'variant': variant, 'phase': phase, 'run_id': rid, 'total_inodes': fs.f_files,
                'free_inodes': fs.f_ffree, 'available_bytes': fs.f_bavail * fs.f_frsize,
                'used_bytes': (fs.f_blocks - fs.f_bfree) * fs.f_frsize}
        if variant == 'inode':
            if phase == 'fault':
                m.require(fs.f_ffree == 0 and fs.f_bavail > 0, 'NOT_INODE_EXHAUSTION')
                try:
                    m.probe_writable(mount)
                except OSError as exc:
                    m.require(exc.errno == errno.ENOSPC, 'UNEXPECTED_WRITE_FAILURE')
                else:
                    raise m.Refused('WRITE_UNEXPECTEDLY_SUCCEEDED')
            else:
                m.require(fs.f_ffree * 10 >= fs.f_files, 'INODES_NOT_RECOVERED')
                m.probe_writable(mount)
        else:
            refs = deleted.open_deleted_refs(state['payload_dev'], state['payload_ino'])
            info['owned_deleted_fds'] = refs
            if phase == 'fault':
                m.require(refs > 0 and info['used_bytes'] >= deleted.SIZE, 'DELETED_OPEN_NOT_OBSERVED')
            else:
                m.require(refs == 0, 'OWNED_DELETED_FD_REMAINS')
                m.probe_writable(mount)
        return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('variant', choices=('inode', 'deleted-open'))
    parser.add_argument('phase', choices=('fault', 'recovered'))
    parser.add_argument('run_id')
    args = parser.parse_args()
    print(json.dumps(observe(args.variant, args.phase, args.run_id)))


if __name__ == '__main__':
    try:
        main()
    except (m.Refused, OSError, ValueError) as exc:
        print(json.dumps({'status': 'FAIL_CLOSED', 'error': str(exc)}), file=sys.stderr)
        sys.exit(2)
