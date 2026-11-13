#!/usr/bin/env python3
"""Compatibility shim; the protected controller owns all N03 operations."""
import hashlib
import os
import stat
import sys

DIGEST = '8b527cad68557f7294be8580f58923c5e7a1563daf521b44087d19724bed6d5c'

def main():
    dfd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in ('usr', 'local', 'libexec', 'opsdrill', 'n03'):
            st = os.fstat(dfd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise RuntimeError('unsafe N03 path')
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
            os.close(dfd); dfd = new
        st = os.fstat(dfd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError('unsafe N03 directory')
        fd = os.open('n03_502.py', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    finally:
        os.close(dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_mode & 0o022 or st.st_size > 131072:
            raise RuntimeError('unsafe N03 controller')
        data = b''
        while len(data) <= 131072:
            chunk = os.read(fd, min(16384, 131073 - len(data)))
            if not chunk: break
            data += chunk
        if len(data) != st.st_size or hashlib.sha256(data).hexdigest() != DIGEST:
            raise RuntimeError('N03 controller version mismatch')
        os.lseek(fd, 0, os.SEEK_SET)
        os.set_inheritable(fd, True)
        os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', '-B', '/proc/self/fd/' + str(fd), *sys.argv[1:]],
                  {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'})
    finally:
        os.close(fd)

if __name__ == '__main__':
    try: main()
    except (OSError, RuntimeError) as exc:
        print('N03 compatibility shim refused: ' + str(exc), file=sys.stderr)
        sys.exit(2)
