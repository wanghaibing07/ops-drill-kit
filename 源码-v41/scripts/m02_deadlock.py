#!/usr/bin/env python3
"""Compatibility import for M02 exercises and a guarded command forwarder."""
import hashlib
import os
from pathlib import Path
import stat
import sys

if __name__ == '__main__':
    if os.geteuid() == 0:
        sys.exit('Use the root-controlled M02 launcher directly; do not sudo a project-owned wrapper.')
    os.execv('/usr/bin/sudo', ['/usr/bin/sudo', '--', '/usr/bin/python3.11', '-I', '-S', '-B',
             '/usr/local/libexec/opsdrill/m02/m02_launcher.py', *sys.argv[1:]])

def _load_compatible_controller():
    digest='5d41a8b7feb577b22a358f3497e1a4eb1c53669a1fbf179a49ca9add16c065c9'
    if os.geteuid() == 0:
        path=Path('/usr/local/libexec/opsdrill/m02/m02_deadlock.py')
        for part in (path.parent,*path.parent.parents):
            st=part.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise ImportError('M02 controller directory is not root-controlled')
    else:
        path=Path(__file__).resolve().parent.parent/'drills/mysql/M02/m02_deadlock.py'
    fd=os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno()); data=f.read(1048577)
    if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or len(data)>1048576
            or (os.geteuid() == 0 and (st.st_uid != 0 or st.st_mode & 0o022))
            or hashlib.sha256(data).hexdigest()!=digest):
        raise ImportError('M02 controller differs from reviewed version')
    exec(compile(data,str(path),'exec'),globals())

_load_compatible_controller()
