#!/usr/bin/env python3
"""Install a fixed, reviewed L02 module set into a root-controlled directory.

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

MANIFEST = {'l02_audit.py': 'fbed2c8254298d2a1a949ba67445729934edf3ab81851d9b6f7c88878094683f', 'l02_cli.py': '553d98696b7b57f15619681d381c2b7e445fed2dfce6857d62c7fcc2a26a87ab', 'l02_config_lifecycle.py': 'a0cd65197f4411340eba0a133096e477212f880e08729e9ad372c1faa905c4bc', 'l02_initialize.py': 'f4b9dce0af162aa4dd7b46e7baffed02690cda71d918435b7e9bd15df8999a59', 'l02_isolated.py': '73b1d0119f2e25b807ae6555ff6aaa5196865aa89280fbbf68917944b1aecedc', 'l02_journal_avc.py': '9b1433956277e122134d536adab232b92f7589f6b4d27715c850518c923f1d8e', 'l02_linux_config.py': 'e20aa533d9151ca868c2c14ecc46f3914888f2a1cee7c5969bde95d9c6e66078', 'l02_linux_config_backend.py': 'b521fe01a23a6539a27810a92d48702079ae96321a41dd40f1518c4ff7a168ce', 'l02_linux_evidence.py': 'f1be95bdc198e346209aa8ac3e7b37260654b08080336fb61edf5b6d6ee12bcd', 'l02_linux_inspect.py': '6614d7e15b1d93ee9a14a2ddcdfa4809bc7bc5c92db3e2d559019fdb32e4c8f4', 'l02_linux_journal.py': '82ddac3719b4a550007bc4806bae15a9c66ee7af3e12a12524939a8dfc0c239b', 'l02_policy.py': '1f0256043cd16b373673c088740581fec810fa1db0d600fdcd91a256fa0b5445', 'l02_prepare.py': '55188b443644f17e5632074df20e1e1a7f8deea4215b21e962df73a9e5015bff', 'l02_watchdog_arm.py': 'ab58c9c75415c4cc643fde355e8996c68948fa0aedf479a4f6df6711e7fdacc8', 'l02_watchdog_helper.py': 'e03d4bdbf157f629603202d6a3e2b83fbebf0f8b425ad2e1f1108a73d0f5d52d'}
TARGET = Path('/usr/local/libexec/opsdrill/l02-recovery-v2')


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
        require(name.startswith('l02_') and name.endswith('.py') and '/' not in name and '\\' not in name,
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
        for part in ('usr','local','libexec','opsdrill','l02-recovery-v2'):
            try: os.mkdir(part,0o755,dir_fd=fd)
            except FileExistsError: pass
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            st=os.fstat(child)
            if not (stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022):
                os.close(child); raise Refused('unsafe installation directory')
            os.close(fd); fd=child
        require(set(os.listdir(fd)) <= set(MANIFEST),'unknown file in L02 installation directory')
        missing=[]
        for name,data in files.items():
            try: old=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            except FileNotFoundError: missing.append(name); continue
            require(hashlib.sha256(safe_file(old)).hexdigest()==MANIFEST[name],
                    'existing module differs; inspect before upgrade: '+name)
        for name in missing:
            temp='.l02-'+secrets.token_hex(16)
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
    require(len(sys.argv)==2,'usage: install_l02.py REVIEWED_SOURCE_DIR')
    guard(); data=source_files(sys.argv[1]); count=install(data)
    print('L02 verified module set installed; new files:',count)


if __name__=='__main__':
    try: main()
    except (Refused,OSError,ValueError,subprocess.SubprocessError) as exc:
        print('L02 install refused:',exc,file=sys.stderr); sys.exit(2)
