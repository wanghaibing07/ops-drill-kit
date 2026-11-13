"""Root-owned config replacement primitive for L02.

Linux-specific; caller must hold the project lock and validate every parent
and the service identity before invoking. This cannot serialize another root
process that ignores the lock. It never edits system nginx configuration.
"""
import hashlib
import os
import secrets
import stat
from l02_policy import require

MAX_CONFIG=8192


def digest(data): return hashlib.sha256(data).hexdigest()


def verify_config_fd(fd,expected):
    st=os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
            stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=MAX_CONFIG,'unsafe config')
    data=os.read(fd,MAX_CONFIG+1)
    require(len(data)==st.st_size and digest(data)==expected,'config changed')
    return st,data


def replace_config(dir_fd,name,expected_sha,new_data):
    require(name=='nginx.conf','invalid config name')
    require(isinstance(new_data,bytes) and 0<len(new_data)<=MAX_CONFIG,'invalid new config')
    current=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dir_fd)
    try:
        st,_=verify_config_fd(current,expected_sha)
        temporary='.config-'+secrets.token_hex(16)
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dir_fd)
        try:
            os.fchmod(fd,0o600)
            view=memoryview(new_data)
            while view:
                n=os.write(fd,view); require(n>0,'write failed'); view=view[n:]
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            try: os.unlink(temporary,dir_fd=dir_fd)
            except FileNotFoundError: pass
            raise
        else: os.close(fd)
        # Re-open and compare identity and content, then atomically replace.
        # The project lock does not protect against hostile concurrent root.
        try:
            check=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dir_fd)
            try:
                now,_=verify_config_fd(check,expected_sha)
                require((st.st_dev,st.st_ino)==(now.st_dev,now.st_ino),'config identity changed')
            finally: os.close(check)
            os.replace(temporary,name,src_dir_fd=dir_fd,dst_dir_fd=dir_fd)
            os.fsync(dir_fd)
        except BaseException:
            try: os.unlink(temporary,dir_fd=dir_fd)
            except FileNotFoundError: pass
            raise
    finally: os.close(current)
    return digest(new_data)
