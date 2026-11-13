#!/usr/bin/env python3
"""Install the reviewed N01 controller and its watchdog into the lab."""
import hashlib
import os
import secrets
import stat
import subprocess
import sys

MANIFEST = {
    'n01.py': '954c3bc7f4e4c59156d7ae612ae107de76ee21204cf8333ce989a721cd5cc8a8',
    'n01_watchdog.py': '183545f5421be32e41281be0ca340fe248436095902bf2b6969fce287c4976be',
}
LIMIT = 1048576

class Refused(Exception): pass

def read_checked(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno()); data = f.read(LIMIT + 1)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > LIMIT or len(data) > LIMIT or hashlib.sha256(data).hexdigest() != expected:
        raise Refused('source is unsafe or differs from reviewed digest: ' + path)
    return data

def lab_guard():
    if os.geteuid() != 0: raise Refused('root required')
    fd = os.open('/etc/opsdrill-lab', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno()); data = f.read(257)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_mode & 0o022 or st.st_size > 256 or data.strip() != b'ops-drill-kit':
        raise Refused('unsafe or invalid lab marker')
    cp = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], capture_output=True, text=True, timeout=10)
    if cp.returncode or cp.stdout.strip() != 'vmware': raise Refused('VMware guest required')

def safe_dir(fd):
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022: raise Refused('unsafe installation directory')

def existing(fd, name, expected):
    try: f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError: return False
    with os.fdopen(f, 'rb') as stream:
        st = os.fstat(stream.fileno()); data = stream.read(LIMIT + 1)
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_mode & 0o022
            or len(data) > LIMIT or hashlib.sha256(data).hexdigest() != expected):
        raise Refused('existing file differs or is unsafe; inspect before upgrade: ' + name)
    return True

def install_at(fd, sources):
    safe_dir(fd)
    # Validate both existing names before creating either. An old controller is
    # deliberately refused: upgrading an active installation is a separate job.
    present = {name: existing(fd, name, digest) for name, digest in MANIFEST.items()}
    for name in ('n01_watchdog.py', 'n01.py'):
        if present[name]: continue
        tmp = '.n01-stage-' + secrets.token_hex(12)
        out = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            with os.fdopen(out, 'wb') as f:
                f.write(sources[name]); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(), 0o755); os.fsync(f.fileno())
            os.link(tmp, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(tmp, dir_fd=fd); os.fsync(fd)
        finally:
            try: os.unlink(tmp, dir_fd=fd)
            except FileNotFoundError: pass
    return sum(not value for value in present.values())

def install(sources):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        safe_dir(fd)
        for component in ('usr', 'local', 'libexec', 'opsdrill', 'n01'):
            try: os.mkdir(component, mode=0o755, dir_fd=fd)
            except FileExistsError: pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try: safe_dir(child)
            except Exception: os.close(child); raise
            os.close(fd); fd = child
        return install_at(fd, sources)
    finally: os.close(fd)

def main(argv):
    if len(argv) != 3: raise Refused('usage: install_n01.py CONTROLLER_SOURCE WATCHDOG_SOURCE')
    lab_guard()
    sources = {name: read_checked(path, MANIFEST[name]) for name, path in zip(MANIFEST, argv[1:])}
    count = install(sources)
    print('N01 verified; installed %d file(s)' % count)

if __name__ == '__main__':
    try: main(sys.argv)
    except (Refused, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        print('N01 install refused or failed:', exc, file=sys.stderr); sys.exit(2)
