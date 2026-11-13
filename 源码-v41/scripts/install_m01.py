#!/usr/bin/env python3
"""Install a fixed, reviewed M01 module set into a root-controlled directory.

The manifest is generated from the reviewed candidate by make_installer.py.
Existing differing files and unknown directory entries are never overwritten.
"""
import hashlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

MANIFEST = {'m01_core.py': 'a86235b38a7f26713b819832b42b2eb0b2d6b280b69e528d9e91b64dbc31747d', 'm01_owned.py': '8b40779dd53458876a32d8312714b071ce186e9788b878fb263dbafb99fbc79f', 'm01_watchdog.py': 'a546052e9bea13ff0c8c8781e9ea317ee788753503ff1d896639347aa07342df'}
TARGET = Path('/usr/local/libexec/opsdrill/m01')


class Refused(Exception): pass


def require(value,message):
    if not value: raise Refused(message)


def guard():
    require(os.geteuid()==0,'root required')
    fd=os.open('/etc/opsdrill-lab',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode & 0o022 and
                st.st_size<=64 and os.read(fd,65).strip()==b'ops-drill-kit','unsafe lab marker')
    finally: os.close(fd)
    proc=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],stdin=subprocess.DEVNULL,
                        capture_output=True,text=True,timeout=10,check=False)
    require(proc.returncode==0 and proc.stdout.strip()=='vmware','VMware guest required')


def safe_file(fd):
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode & 0o022 and
                st.st_size<=1024*1024,'unsafe target module')
        return f.read()


def source_files(source):
    require(MANIFEST,'empty reviewed manifest')
    result={}
    for name,digest in MANIFEST.items():
        require(name.startswith('m01_') and name.endswith('.py') and '/' not in name and '\\' not in name,
                'invalid module name')
        fd=os.open(Path(source)/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as f:
            st=os.fstat(f.fileno())
            require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=1024*1024,'unsafe source module')
            data=f.read()
        require(hashlib.sha256(data).hexdigest()==digest,'source module version mismatch: '+name)
        result[name]=data
    return result


def install(files,root_dir='/'):
    fd=os.open(root_dir,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in ('usr','local','libexec','opsdrill','m01'):
            try: os.mkdir(part,0o755,dir_fd=fd)
            except FileExistsError: pass
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            st=os.fstat(child)
            if not (stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022):
                os.close(child); raise Refused('unsafe installation directory')
            os.close(fd); fd=child
        require(set(os.listdir(fd)) <= set(MANIFEST),'unknown file in M01 installation directory')
        missing=[]
        for name,data in files.items():
            try: old=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            except FileNotFoundError: missing.append(name); continue
            require(hashlib.sha256(safe_file(old)).hexdigest()==MANIFEST[name],
                    'existing module differs; inspect before upgrade: '+name)
        for name in missing:
            temp='.m01-'+secrets.token_hex(16)
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
    require(len(sys.argv)==2,'usage: install_m01.py REVIEWED_SOURCE_DIR')
    guard(); data=source_files(sys.argv[1]); count=install(data)
    print('M01 verified module set installed; new files:',count)


if __name__=='__main__':
    try: main()
    except (Refused,OSError,ValueError,subprocess.SubprocessError) as exc:
        print('M01 install refused:',exc,file=sys.stderr); sys.exit(2)
