"""Root-protected persistent L02 journal, Linux only.

This stores state safely but is not a policy lock and does not authorize a
semanage operation. Callers must hold `locked()` for a complete transaction.
"""
import contextlib
import fcntl
import json
import os
import re
import secrets
import stat
from l02_policy import Refused, require

BASE='/var/lib/opsdrill'
NAME='l02-journal'
RUN=re.compile(r'^[0-9a-f]{24}$')


def check_dir(fd, exact_mode=None):
    st=os.fstat(fd)
    require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022, 'unsafe journal directory')
    if exact_mode is not None: require(stat.S_IMODE(st.st_mode)==exact_mode,'unsafe journal mode')


def check_file(fd):
    st=os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
            stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=32768,'unsafe journal file')
    return st


def unique(pairs):
    obj={}
    for key,value in pairs:
        require(key not in obj,'duplicate journal field')
        obj[key]=value
    return obj


def validate_record(record,rid):
    require(RUN.fullmatch(rid or '') is not None, 'bad run id')
    require(isinstance(record,dict) and record.get('version')==1 and record.get('run_id')==rid and
            record.get('phase') in ('PREPARED','FAULT_PENDING','FAULT','ADD_INTENT','RESOLVED',
                                    'REMOVE_INTENT','REPAIR_INTENT','REPAIRED','RESET_INTENT','RESTORED','NEEDS_REVIEW'), 'invalid journal record')
    data=(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')
    require(len(data)<=32768,'journal record too large')
    return data


def write_all(fd,data):
    data=memoryview(data)
    while data:
        n=os.write(fd,data); require(n>0,'journal write failed'); data=data[n:]

class Journal:
    def __init__(self,create=False):
        require(os.geteuid()==0,'root required')
        # Anchor resolution at / and verify each directory, rejecting symlinks.
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            for part in ('var','lib','opsdrill'):
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                try: check_dir(child)
                except Exception: os.close(child); raise
                os.close(parent); parent=child
            if create:
                try:
                    os.mkdir(NAME,0o700,dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError: pass
            self.fd=os.open(NAME,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            try: check_dir(self.fd,0o700)
            except Exception: os.close(self.fd); raise
        finally: os.close(parent)

    def close(self): os.close(self.fd)

    @contextlib.contextmanager
    def locked(self):
        fd=os.open('.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            check_file(fd); fcntl.flock(fd,fcntl.LOCK_EX); yield
        finally: os.close(fd)

    def read(self,rid):
        require(RUN.fullmatch(rid or '') is not None,'bad run id')
        try: fd=os.open(rid+'.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
        except FileNotFoundError: return None
        try:
            st=check_file(fd); data=os.read(fd,32769)
            require(len(data)==st.st_size,'journal changed during read')
            obj=json.loads(data,object_pairs_hook=unique)
            validate_record(obj,rid)
            return obj
        finally: os.close(fd)

    def save(self,rid,record):
        data=validate_record(record,rid)
        # Reject existing suspicious destination before atomic replacement.
        self.read(rid)
        temp='.tmp-'+secrets.token_hex(16)
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
        try:
            os.fchmod(fd,0o600); write_all(fd,data); os.fsync(fd)
        except Exception:
            os.close(fd)
            try: os.unlink(temp,dir_fd=self.fd)
            except FileNotFoundError: pass
            raise
        else: os.close(fd)
        os.replace(temp,rid+'.json',src_dir_fd=self.fd,dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def remove(self,rid,expected):
        """Remove only the exact, still-owned completed record under the lock."""
        require(self.read(rid)==expected,'journal changed before cleanup')
        fd=os.open(rid+'.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
        try:
            st=check_file(fd); data=os.read(fd,32769)
            require(len(data)==st.st_size and json.loads(data,object_pairs_hook=unique)==expected,'journal changed')
            current=os.stat(rid+'.json',dir_fd=self.fd,follow_symlinks=False)
            require((st.st_dev,st.st_ino)==(current.st_dev,current.st_ino),'journal identity changed')
            os.unlink(rid+'.json',dir_fd=self.fd)
            os.fsync(self.fd)
        finally: os.close(fd)
