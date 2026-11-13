#!/usr/bin/env python3
"""Conservative old-N01 to watchdog migration candidate; Linux only.

Requires a quiescent, single-operator maintenance window. Does not update CLI.
Review and test on the isolated lab before use.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import types

OLD_SHA = '96fc2a764a432d08658c4cd0d6521e5f1fb4fca2a7c98f166be753e3240a6ac8'
CONTROLLER_SHA = '954c3bc7f4e4c59156d7ae612ae107de76ee21204cf8333ce989a721cd5cc8a8'
HELPER_SHA = '183545f5421be32e41281be0ca340fe248436095902bf2b6969fce287c4976be'
N02_SHA = 'a22e59d0217ab059b6c32f985094f074d8d553a273c2d3a2cc4065360d3120dc'
N02_PATH = Path('/usr/local/libexec/opsdrill/n02/n02.py')
TARGET_DIR = Path('/usr/local/libexec/opsdrill/n01')
N01_ROOT = Path('/run/opsdrill-n01')
CLI_ROOT = Path('/var/lib/opsdrill/cli')
BACKUP = 'n01.pre-watchdog-' + OLD_SHA + '.py'
MAX_SIZE = 1048576


class Refused(Exception): pass


def digest(data): return hashlib.sha256(data).hexdigest()


def read_file(path, expected=None, root_owned=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_SIZE
                or (root_owned and (st.st_uid != 0 or st.st_mode & 0o022))):
            raise Refused('unsafe file: ' + str(path))
        data = stream.read(MAX_SIZE + 1)
    if len(data) > MAX_SIZE or (expected is not None and digest(data) != expected):
        raise Refused('file digest or size mismatch: ' + str(path))
    return data


def safe_path(path, private=False):
    for part in (path, *path.parents):
        st = part.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused('unsafe directory: ' + str(part))
        if part == path and private and stat.S_IMODE(st.st_mode) != 0o700:
            raise Refused('runtime directory is not private: ' + str(part))


def lab_guard():
    if os.geteuid() != 0: raise Refused('root required')
    marker = Path('/etc/opsdrill-lab')
    safe_path(marker.parent)
    marker_data = read_file(marker, root_owned=True)
    if len(marker_data) > 256 or marker_data.strip() != b'ops-drill-kit': raise Refused('lab marker mismatch')
    cp = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True, text=True, timeout=10)
    if cp.returncode or cp.stdout.strip() != 'vmware': raise Refused('VMware guest required')


def load_n02():
    safe_path(N02_PATH.parent)
    data = read_file(N02_PATH, N02_SHA, root_owned=True)
    module = types.ModuleType('n02_migration_reviewed')
    module.__file__ = str(N02_PATH)
    if module.__name__ in sys.modules: raise Refused('N02 module name already in use')
    sys.modules[module.__name__] = module
    try:
        exec(compile(data, str(N02_PATH), 'exec'), module.__dict__)
    except Exception:
        del sys.modules[module.__name__]
        raise
    return module


def acquire_cli_lock():
    safe_path(CLI_ROOT, private=True)
    fd = os.open(CLI_ROOT/'controller.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise Refused('unsafe CLI lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except Exception:
        os.close(fd)
        raise


def reject_pending_n01(names):
    # All manifests, partial files, sockets and unknown entries block migration.
    # Even a manifest with a receipt is kept for explicit operator review.
    for name in names:
        if not re.fullmatch(r'completed-[0-9a-f]{24}\.json', name):
            raise Refused('N01 pending or unknown runtime entry: ' + name)
        path = N01_ROOT/name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            st = os.fstat(stream.fileno())
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                    or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 512):
                raise Refused('unsafe completion receipt')
            raw = stream.read(513)
        def unique(pairs):
            out = {}
            for key, value in pairs:
                if key in out: raise Refused('duplicate receipt field')
                out[key] = value
            return out
        receipt = json.loads(raw, object_pairs_hook=unique)
        rid = name[len('completed-'):-len('.json')]
        if (len(raw) > 512 or not isinstance(receipt, dict) or type(receipt.get('version')) is not int
                or receipt != {'version':1, 'run_id':rid, 'result':'clean'}):
            raise Refused('invalid completion receipt')


def preflight_locked(n02):
    safe_path(N01_ROOT, private=True)
    safe_path(n02.ROOT, private=True)
    safe_path(TARGET_DIR)
    if any(os.path.lexists(CLI_ROOT/(name+'.json')) for name in ('N01', 'N02')):
        raise Refused('CLI network drill state exists')
    reject_pending_n01(os.listdir(N01_ROOT))
    if n02.load() is not None or set(n02.NAMES) & n02.namespaces():
        raise Refused('N02 state or namespace exists')
    cp = subprocess.run(['/usr/bin/systemctl', 'list-units', '--all', '--plain', '--no-legend',
                         '--no-pager', 'opsdrill-n01-recover-*'],
                        capture_output=True, text=True, timeout=10, check=True)
    if cp.stdout.strip(): raise Refused('N01 recovery systemd units exist')


def write_new(dirfd, name, data):
    """Create a new file without replacing an existing name."""
    tmp = '.n01-stage-' + secrets.token_hex(12)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dirfd)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o755); os.fsync(stream.fileno())
        os.link(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
        os.unlink(tmp, dir_fd=dirfd); os.fsync(dirfd)
    finally:
        try: os.unlink(tmp, dir_fd=dirfd)
        except FileNotFoundError: pass


def ensure_file(dirfd, name, data, expected):
    path = TARGET_DIR/name
    if os.path.lexists(path):
        read_file(path, expected, root_owned=True)
    else:
        write_new(dirfd, name, data)
        read_file(path, expected, root_owned=True)


def install_locked(controller, helper):
    if digest(controller) != CONTROLLER_SHA or digest(helper) != HELPER_SHA:
        raise Refused('candidate source digest mismatch')
    target = TARGET_DIR/'n01.py'
    old = read_file(target, root_owned=True)
    if digest(old) not in (OLD_SHA, CONTROLLER_SHA): raise Refused('unrecognized installed controller')
    if digest(old) == CONTROLLER_SHA:
        read_file(TARGET_DIR/BACKUP, OLD_SHA, root_owned=True)
    dirfd = os.open(TARGET_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if digest(old) == OLD_SHA: ensure_file(dirfd, BACKUP, old, OLD_SHA)
        # Never replace an existing helper, even if the runtime appears clean.
        ensure_file(dirfd, 'n01_watchdog.py', helper, HELPER_SHA)
        if digest(old) == OLD_SHA:
            stage = '.n01-controller-' + secrets.token_hex(12)
            write_new(dirfd, stage, controller)
            try:
                # Refuse if the original controller changed during preparation.
                if read_file(target, OLD_SHA, root_owned=True) != old: raise Refused('controller changed')
                os.replace(stage, 'n01.py', src_dir_fd=dirfd, dst_dir_fd=dirfd)
                os.fsync(dirfd)
            finally:
                try: os.unlink(stage, dir_fd=dirfd)
                except FileNotFoundError: pass
        read_file(target, CONTROLLER_SHA, root_owned=True)
        read_file(TARGET_DIR/'n01_watchdog.py', HELPER_SHA, root_owned=True)
    finally: os.close(dirfd)


def migrate(controller_path, helper_path):
    lab_guard()
    controller = read_file(controller_path, CONTROLLER_SHA)
    helper = read_file(helper_path, HELPER_SHA)
    n02 = load_n02(); n02.guard()
    cli_fd = acquire_cli_lock()
    try:
        safe_path(n02.ROOT, private=True)
        network_fd = n02.acquire_lock(fcntl, timeout=5)
        if type(network_fd) is not int or network_fd < 0: raise Refused('invalid N02 lock descriptor')
        try:
            preflight_locked(n02)
            install_locked(controller, helper)
        finally: os.close(network_fd)
    finally: os.close(cli_fd)
    print('N01 candidate installed; CLI digest still requires separate verified migration')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3: raise Refused('usage: installer CONTROLLER_SOURCE HELPER_SOURCE')
        migrate(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        print('N01 migration refused or failed: ' + str(exc), file=sys.stderr)
        sys.exit(3)
