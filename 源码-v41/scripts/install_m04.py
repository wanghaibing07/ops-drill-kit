"""Offline M04 installer candidate; run only after independent source review.

No network, no VM access, no existing installation is replaced. All payload
bytes are verified before a private staging directory is created. A failed
installation leaves its staging directory for inspection.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
import sys

# Frozen alongside m04-cli-integration.patch. Do not load an untrusted manifest.
MANIFEST = {'continuation/mysql_backup_gate.py': '3761d0323109a48795f8e222ae4fea4d104bdd56202a362ee0567946fff1b8bb', 'continuation/mysql_binlog_gate.py': 'f35dc69743710157359e1cbb55f4f4b6997b52c687c8f0185843a7a3d97ea917', 'continuation/mysql_fixture_gate.py': '5729222c7028879e36bee1cbfd50d7124cefb0d5459ef290906bce73bc286e15', 'continuation/mysql_lifecycle_candidate.py': '97de74a7581515184b83e716191d932fc43044e13b6419e0655f552027e23885', 'continuation/mysql_live_identity.py': 'c294cfa07973ef9342d4ca65147da14acbe6fa155ad29623edcda31fc48a42be', 'continuation/mysql_reset_gate.py': 'eff466c8ad9dc5f7d2012a1b93aca33ffbb763d52ba8c39429f34ad7623178af', 'continuation/mysql_synthetic_drill.py': '8b03d6c482a420ac9747e4ca5b9898590e22da342a2599eeb1014fd84ebd9249', 'm04_business.py': '17c401b9144efc3d2e0b7b5f72ca20da04220a512b4514a564405b8a35a872ef', 'm04_controller.py': '46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9', 'm04_replay_account.py': '15a112d035563f1a2e8088c4a7c7f8ffc6ee5e7425d3f9ba68a8dfcb1d52234d', 'pitr_audit.py': '3b6d5fa1ee4c5227d3ae33a825b92bac8c96d6b054a80bfda2537ea03cb6c51e', 'sealed_replay.py': '5e8487ab4b6ab7acc6b3dc961456159c9a1ce30a0cce5d784b9d43e503597e7f', 'stream_envelope.py': '95b9307b280e568df1332657e67b525198b4159f3e498c3a5ae3a14128a9c520', 'vm_replay_probe.py': '569af2c7ef921b09d005581d860f64681e78735f019e1d2698672fffbb10da97'}
DEST_PARENT = '/usr/local/libexec/opsdrill'
DEST_NAME = 'm04-synthetic-v1'
LIMIT = 1048576


class InstallRejected(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise InstallRejected(message)


def check_dir(fd):
    st = os.fstat(fd)
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
            'directory is not root-controlled')


def open_absolute_dir(path):
    require(isinstance(path, str) and path.startswith('/') and path != '/', 'absolute directory required')
    parts = path.split('/')[1:]
    require(all(part not in ('', '.', '..') for part in parts), 'noncanonical directory rejected')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        check_dir(fd)
        for part in parts:
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
            check_dir(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def source_bytes(parent_fd, child_fd, name, digest):
    if '/' in name:
        prefix, leaf = name.split('/', 1)
        require(prefix == 'continuation' and '/' not in leaf, 'invalid manifest name')
        directory = child_fd
    else:
        leaf, directory = name, parent_fd
    require(leaf not in ('', '.', '..'), 'invalid manifest name')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(leaf, flags, dir_fd=directory)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                and not st.st_mode & 0o022 and 0 <= st.st_size <= LIMIT, 'unsafe source file')
        data = bytearray()
        while len(data) <= LIMIT:
            part = os.read(fd, min(65536, LIMIT + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        require(len(data) == st.st_size and len(data) <= LIMIT, 'source size changed')
        data = bytes(data)
        require(hashlib.sha256(data).hexdigest() == digest, 'source digest mismatch')
        return data
    finally:
        os.close(fd)


def read_payload(source):
    root = open_absolute_dir(source)
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        child = os.open('continuation', flags, dir_fd=root)
        try:
            check_dir(child)
            return {name: source_bytes(root, child, name, digest) for name, digest in MANIFEST.items()}
        finally:
            os.close(child)
    finally:
        os.close(root)


def write_file(directory_fd, name, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        pos = 0
        while pos < len(data):
            n = os.write(fd, data[pos:])
            require(n > 0, 'short installation write')
            pos += n
        os.fsync(fd)
    finally:
        os.close(fd)


def rename_noreplace(parent_fd, source_name, target_name):
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
    except AttributeError as exc:
        raise InstallRejected('renameat2 unavailable; installation not published') from exc
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(source_name), parent_fd, os.fsencode(target_name), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise InstallRejected('destination already exists')
        raise OSError(code, os.strerror(code))


def install(source):
    require(hasattr(os, 'geteuid') and os.geteuid() == 0, 'root required')
    require(sys.platform.startswith('linux'), 'Linux required')
    payload = read_payload(source)  # reject before creating any installation files
    parent = open_absolute_dir(DEST_PARENT)
    stage = None
    try:
        try:
            os.stat(DEST_NAME, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise InstallRejected('destination already exists')
        stage_name = '.m04-install-' + secrets.token_hex(12)
        os.mkdir(stage_name, 0o700, dir_fd=parent)
        stage = stage_name
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        stage_fd = os.open(stage, flags, dir_fd=parent)
        try:
            os.fchmod(stage_fd, 0o700)
            check_dir(stage_fd)
            os.mkdir('continuation', 0o700, dir_fd=stage_fd)
            child_fd = os.open('continuation', flags, dir_fd=stage_fd)
            try:
                os.fchmod(child_fd, 0o700)
                check_dir(child_fd)
                for name, data in payload.items():
                    directory, leaf = (child_fd, name.split('/', 1)[1]) if name.startswith('continuation/') else (stage_fd, name)
                    write_file(directory, leaf, data)
                os.fsync(child_fd)
            finally:
                os.close(child_fd)
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        os.fsync(parent)
        rename_noreplace(parent, stage, DEST_NAME)
        stage = None
        os.fsync(parent)
    except BaseException:
        if stage:
            print(json.dumps({'status': 'STAGING_RETAINED', 'name': stage}), file=sys.stderr, flush=True)
        raise
    finally:
        os.close(parent)
    return {'status': 'INSTALLED', 'destination': DEST_PARENT + '/' + DEST_NAME,
            'files': len(payload)}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True, help='absolute root-controlled source parent containing continuation/')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(install(args.source), sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'status': 'UNCONFIRMED', 'error_type': type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
