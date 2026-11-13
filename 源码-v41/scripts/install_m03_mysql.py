#!/usr/bin/env python3
"""Install the reviewed M03 files without overwriting existing objects."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

# SHA-256 of the exact source bytes, not newline-normalized text.
MANIFEST = {'mysql_lifecycle.py': 'e1bc6b0895114652781b96c753760fff7ba83f82fad2c4e89f03d5a3de81b457', 'm04_controller.py': '46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9', 'm03_vm_probe.py': '0af53e4b3f18819699d4c68dc44f7a3cdc1ae4abe2696f2b661f92a4bfd53aac'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def guard():
    require(os.geteuid() == 0, 'root required')
    fd = os.open('/etc/opsdrill-lab', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= 64 and
                os.read(fd, 65).strip() == b'ops-drill-kit', 'unsafe lab marker')
    finally:
        os.close(fd)
    result = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'},
                            timeout=10, check=False)
    require(result.returncode == 0 and result.stdout.strip() == 'vmware', 'VMware guest required')


def secure_file(fd):
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= 1024 * 1024, 'unsafe file')
        data = stream.read(1024 * 1024 + 1)
        require(len(data) == st.st_size, 'file changed')
        return data


def source_files(source):
    path = Path(source).absolute()
    for item in (path, *path.parents):
        st = os.lstat(item)
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'unsafe source directory')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        result = {}
        for name, digest in MANIFEST.items():
            data = secure_file(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd))
            require(hashlib.sha256(data).hexdigest() == digest, 'source digest mismatch: ' + name)
            result[name] = data
    finally:
        os.close(fd)
    result['manifest.json'] = (json.dumps(MANIFEST, sort_keys=True) + '\n').encode('ascii')
    return result


def secure_installer():
    path = Path(__file__).absolute()
    for parent in path.parents:
        st = os.lstat(parent)
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'unsafe installer directory')
    secure_file(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC))


def install(files, root='/'):
    require(set(files) == set(MANIFEST) | {'manifest.json'}, 'invalid module set')
    expected = dict(MANIFEST)
    expected['manifest.json'] = hashlib.sha256((json.dumps(MANIFEST, sort_keys=True) + '\n').encode('ascii')).hexdigest()
    require(all(hashlib.sha256(files[name]).hexdigest() == digest for name, digest in expected.items()),
            'invalid install content')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in ('usr', 'local', 'libexec', 'opsdrill', 'm03-mysql-v1'):
            try:
                os.mkdir(part, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            st = os.fstat(child)
            if not (stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022):
                os.close(child)
                raise RuntimeError('unsafe installation directory')
            os.close(fd)
            fd = child
        require(set(os.listdir(fd)) <= set(expected), 'unknown installation file')
        missing = []
        for name, digest in expected.items():
            try:
                item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                missing.append(name)
                continue
            require(hashlib.sha256(secure_file(item)).hexdigest() == digest, 'existing file differs: ' + name)
        for name in missing:
            temp = '.m03-' + secrets.token_hex(16)
            out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                with os.fdopen(out, 'wb') as stream:
                    stream.write(files[name])
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o644)
                    os.fsync(stream.fileno())
                os.link(temp, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                os.unlink(temp, dir_fd=fd)
            finally:
                try:
                    os.unlink(temp, dir_fd=fd)
                except FileNotFoundError:
                    pass
        os.fsync(fd)
        return len(missing)
    finally:
        os.close(fd)


def main():
    require(len(sys.argv) == 2, 'usage: install_m03.py REVIEWED_SOURCE_DIR')
    guard()
    # Caller must independently authenticate this installer; ownership is not provenance.
    secure_installer()
    count = install(source_files(sys.argv[1]))
    print('M03 installed; new files:', count)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('M03 install refused:', exc, file=sys.stderr)
        sys.exit(2)
