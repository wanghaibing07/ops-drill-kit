#!/usr/bin/env python3
"""Install the pinned L04 controller and service without replacing existing files."""
import hashlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

MANIFEST={'controller.py':'795ee1a568148b6c58975a90b18f9dcb67226d646dfce83a58220e045b61255a',
          'service.py':'e1c2b9ad03adf59f3af4052c931ebe08630c407c82e0ac90bfd1366a4b3cd9d0'}


class Refused(Exception): pass


def require(ok, message):
    if not ok: raise Refused(message)


def guard():
    require(os.geteuid()==0,'root required')
    fd=os.open('/etc/opsdrill-lab',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
                not st.st_mode & 0o022 and st.st_size<=64 and os.read(fd,65).strip()==b'ops-drill-kit',
                'unsafe lab marker')
    finally: os.close(fd)
    proc=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],stdin=subprocess.DEVNULL,
                        capture_output=True,text=True,timeout=10,check=False)
    require(proc.returncode==0 and proc.stdout.strip()=='vmware','VMware guest required')


def read_file(fd, target=False):
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=1048576 and
                (not target or (st.st_uid==0 and not st.st_mode & 0o022)), 'unsafe module')
        return f.read(1048577)


def source_files(source):
    data={}
    for name,digest in MANIFEST.items():
        fd=os.open(Path(source)/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        content=read_file(fd)
        require(hashlib.sha256(content).hexdigest()==digest,'source digest mismatch: '+name)
        data[name]=content
    return data


def install(files, root='/'):
    require(set(files)==set(MANIFEST) and all(hashlib.sha256(files[n]).hexdigest()==MANIFEST[n] for n in MANIFEST),
            'unverified source set')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,'unsafe root')
        for part in ('usr','local','libexec','opsdrill','l04'):
            try: os.mkdir(part,0o755,dir_fd=fd)
            except FileExistsError: pass
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            st=os.fstat(child)
            if not (stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022):
                os.close(child); raise Refused('unsafe target directory')
            os.close(fd); fd=child
        entries=set(os.listdir(fd))
        require(not entries-set(MANIFEST)-{'runtime'},'unknown target entry')
        if 'runtime' in entries:
            st=os.stat('runtime',dir_fd=fd,follow_symlinks=False)
            require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,
                    'unsafe runtime directory')
        missing=[]
        for name,digest in MANIFEST.items():
            try: old=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            except FileNotFoundError: missing.append(name); continue
            require(hashlib.sha256(read_file(old,True)).hexdigest()==digest,'existing module differs: '+name)
        for name in missing:
            temp='.l04-'+secrets.token_hex(16)
            out=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
            try:
                with os.fdopen(out,'wb') as f:
                    f.write(files[name]); f.flush(); os.fchmod(f.fileno(),0o644); os.fsync(f.fileno())
                os.link(temp,name,src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False)
                os.unlink(temp,dir_fd=fd)
            finally:
                try: os.unlink(temp,dir_fd=fd)
                except FileNotFoundError: pass
        os.fsync(fd)
        return len(missing)
    finally: os.close(fd)


def main():
    require(len(sys.argv)==2,'usage: install_l04.py REVIEWED_SOURCE_DIR')
    guard()
    count=install(source_files(sys.argv[1]))
    print('L04 pinned files installed; new files:',count)


if __name__=='__main__':
    try: main()
    except (Refused,OSError,ValueError,subprocess.SubprocessError) as exc:
        print('L04 install refused:',exc,file=sys.stderr); sys.exit(2)
