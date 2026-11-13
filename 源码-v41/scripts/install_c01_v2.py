#!/usr/bin/env python3
"""Install a reviewed C01 v2 controller from a root-controlled source file."""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys

DIGEST = '29b84c493a889ff2ea6b624f23e3e98f6a15096eed5a648e676bed08d928b60a'
DEST = Path('/usr/local/libexec/opsdrill/c01-v2')


def check_chain(path):
    for part in (path, *path.parents):
        st=part.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
            raise RuntimeError('unsafe directory')


def read_verified(path):
    check_chain(path.parent)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022 or st.st_size>131072:
            raise RuntimeError('unsafe source')
        data=b''
        while len(data)<=131072:
            chunk=os.read(fd,16384)
            if not chunk:break
            data+=chunk
        if len(data)!=st.st_size or hashlib.sha256(data).hexdigest()!=DIGEST:
            raise RuntimeError('source digest mismatch')
        return data
    finally:os.close(fd)


def main():
    if len(sys.argv)!=2 or os.geteuid()!=0:raise RuntimeError('root and a source file are required')
    # The operator must verify this installer before executing it as root.
    check_chain(Path(__file__).absolute().parent)
    st=Path(__file__).lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_nlink!=1:
        raise RuntimeError('unsafe installer')
    marker=Path('/etc/opsdrill-lab')
    check_chain(marker.parent)
    marker_st=marker.lstat()
    if not stat.S_ISREG(marker_st.st_mode) or marker_st.st_uid!=0 or marker_st.st_mode&0o022 or marker.read_bytes().strip()!=b'ops-drill-kit':
        raise RuntimeError('invalid lab marker')
    if subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,check=True,text=True).stdout.strip()!='vmware':
        raise RuntimeError('VMware required')
    data=read_verified(Path(sys.argv[1]).absolute())
    check_chain(DEST.parent)
    if os.path.lexists(DEST):
        check_chain(DEST)
        if set(os.listdir(DEST))!={'c01_control.py'} or read_verified(DEST/'c01_control.py')!=data:
            raise RuntimeError('existing installation differs')
        print('C01 v2 already installed and verified')
        return
    DEST.mkdir(mode=0o755)
    dfd=os.open(DEST,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open('c01_control.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644,dir_fd=dfd)
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fchmod(f.fileno(),0o644);os.fsync(f.fileno())
        os.fsync(dfd)
    finally:os.close(dfd)
    subprocess.run(['/usr/sbin/restorecon','-R',str(DEST)],check=True)
    if read_verified(DEST/'c01_control.py')!=data:raise RuntimeError('installation verification failed')
    print('C01 v2 installed')


if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,subprocess.SubprocessError) as e:
        print('C01 installation refused:',type(e).__name__,file=sys.stderr)
        sys.exit(1)
