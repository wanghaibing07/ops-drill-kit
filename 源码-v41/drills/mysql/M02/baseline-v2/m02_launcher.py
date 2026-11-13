#!/usr/bin/python3.11
"""Run the M02 controller with isolated, system-package-only imports."""
import os
import runpy
import stat
import sys
from pathlib import Path

SITE = Path('/usr/lib/python3.11/site-packages')
PLAT_SITE = Path('/usr/lib64/python3.11/site-packages')
CONTROLLER = Path('/usr/local/libexec/opsdrill/m02-baseline-v2/m02_deadlock.py')


def trusted(st, directory=False):
    return (st.st_uid == 0 and not st.st_mode & 0o022 and
            (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)))


def check_site(path):
    # -S disables site initialization and .pth files. Reject writable or
    # symlinked descendants before adding the RPM-managed package directory.
    for item in (path, *path.parents):
        if not trusted(item.lstat(), True):
            raise RuntimeError('untrusted system Python package path')
    for root, dirs, files in os.walk(path, followlinks=False, onerror=lambda exc: (_ for _ in ()).throw(exc)):
        for name in dirs:
            if not trusted(os.lstat(os.path.join(root,name)), True):
                raise RuntimeError('untrusted package directory')
        for name in files:
            if not trusted(os.lstat(os.path.join(root,name))):
                raise RuntimeError('untrusted package file')


def main():
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise RuntimeError('requires Python -I -S -B')
    if os.geteuid() != 0:
        raise RuntimeError('root required')
    os.environ.clear()
    os.environ.update({'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C', 'LANG':'C'})
    for site in (SITE, PLAT_SITE):
        check_site(site)
    sys.path[:0] = [str(SITE), str(PLAT_SITE)]
    # The RPM and this import location are verified by the installer.
    import pymysql
    if Path(pymysql.__file__).parent != SITE / 'pymysql':
        raise RuntimeError('unexpected PyMySQL location')
    sys.argv[0] = str(CONTROLLER)
    runpy.run_path(str(CONTROLLER), run_name='__main__')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ImportError) as exc:
        print('M02 launcher refused:', exc, file=sys.stderr)
        sys.exit(2)
