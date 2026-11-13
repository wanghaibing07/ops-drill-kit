#!/usr/bin/env python3
"""Install one reviewed N02 controller into a root-controlled fixed location."""
import hashlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

EXPECTED = 'a22e59d0217ab059b6c32f985094f074d8d553a273c2d3a2cc4065360d3120dc'
TARGET = '/usr/local/libexec/opsdrill/n02/n02.py'


class Refused(Exception): pass


def read_source(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 1024 * 1024:
            raise Refused('Source must be a bounded regular file with one link')
        with os.fdopen(fd, 'rb') as stream:
            fd = -1
            data = stream.read(1024 * 1024 + 1)
        if hashlib.sha256(data).hexdigest() != EXPECTED:
            raise Refused('Source digest does not match reviewed N02 version')
        return data
    finally:
        if fd != -1: os.close(fd)


def require_lab():
    if os.geteuid() != 0: raise Refused('root required')
    marker = Path('/etc/opsdrill-lab')
    st = marker.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_nlink != 1:
        raise Refused('Unsafe lab marker')
    if marker.read_text(encoding='utf-8').strip() != 'ops-drill-kit': raise Refused('Lab marker mismatch')
    cp = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True, text=True, timeout=10)
    if cp.returncode or cp.stdout.strip() != 'vmware': raise Refused('VMware guest required')


def safe_directory(fd):
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Refused('Installation parent is not root-controlled')


def install(data):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        safe_directory(fd)
        for component in ('usr', 'local', 'libexec', 'opsdrill', 'n02'):
            try: os.mkdir(component, mode=0o755, dir_fd=fd)
            except FileExistsError: pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try: safe_directory(child)
            except Exception:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        try:
            existing = os.open('n02.py', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            with os.fdopen(existing, 'rb') as stream:
                st = os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_nlink != 1 or st.st_size > 1024 * 1024:
                    raise Refused('Existing controller is unsafe')
                if hashlib.sha256(stream.read()).hexdigest() != EXPECTED:
                    raise Refused('Different controller already installed; inspect before upgrade')
            return False
        tmp = '.n02-' + secrets.token_hex(12)
        out = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            with os.fdopen(out, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o755)
                os.fsync(stream.fileno())
            os.link(tmp, 'n02.py', src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(tmp, dir_fd=fd)
            os.fsync(fd)
        finally:
            try: os.unlink(tmp, dir_fd=fd)
            except FileNotFoundError: pass
        return True
    finally:
        os.close(fd)


def main(argv):
    if len(argv) != 2:
        raise Refused('Usage: install_n02.py REVIEWED_N02_SOURCE')
    require_lab()
    data = read_source(argv[1])
    print(('Installed ' if install(data) else 'Already installed ') + TARGET)


if __name__ == '__main__':
    try: main(sys.argv)
    except (Refused, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        print('N02 install refused or failed:', exc, file=sys.stderr)
        sys.exit(2)
