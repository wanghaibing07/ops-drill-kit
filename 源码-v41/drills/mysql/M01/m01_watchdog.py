#!/usr/bin/env python3
"""Restore one owned M01 index visibility; preserve state for explicit reset."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

BASE=Path('/var/lib/opsdrill/m01')
HELPER=Path('/usr/local/libexec/opsdrill/m01/m01_watchdog.py')
ADMIN='/etc/opsdrill/mysql-admin.cnf'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}


class Refused(Exception): pass
def require(value,message):
    if not value: raise Refused(message)


def secure_file(path,exact_mode=None):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
                not st.st_mode & 0o022 and st.st_size<=1048576,'unsafe protected file')
        if exact_mode is not None: require(stat.S_IMODE(st.st_mode)==exact_mode,'unsafe protected file mode')
        with os.fdopen(fd,'rb') as f:
            fd=-1; return f.read()
    finally:
        if fd>=0: os.close(fd)


def helper_digest():
    require(Path(os.path.abspath(__file__))==HELPER,'unexpected helper path')
    for p in HELPER.parents:
        st=p.lstat(); require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,'unsafe helper parent')
    return hashlib.sha256(secure_file(HELPER)).hexdigest()


def guard():
    require(os.geteuid()==0,'root required')
    require(secure_file('/etc/opsdrill-lab').strip()==b'ops-drill-kit','invalid lab marker')
    for parent in Path(ADMIN).parents:
        st=parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,'unsafe MySQL configuration parent')
    secure_file(ADMIN,0o600)
    p=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],stdin=subprocess.DEVNULL,
                     capture_output=True,text=True,timeout=10,check=False,env=ENV)
    require(p.returncode==0 and p.stdout.strip()=='vmware','VMware required')


def read_owned(rid,digest,boot):
    data=secure_file(BASE/'state.json',0o600)
    require(len(data)<=4096,'oversized state')
    def unique(pairs):
        out={}
        for key,value in pairs:
            require(key not in out,'duplicate state field'); out[key]=value
        return out
    state=json.loads(data,object_pairs_hook=unique)
    if isinstance(state,dict) and state.get('id')=='M01' and state.get('version')==2 and state.get('run_id')!=rid:
        return None
    require(isinstance(state,dict) and state.get('id')=='M01' and state.get('version')==2 and
            state.get('run_id')==rid and state.get('boot_id')==boot and
            state.get('timer')=='opsdrill-m01-recover-'+rid+'.timer' and
            state.get('helper_sha256')==digest and isinstance(state.get('globals'),dict),'M01 state mismatch')
    return state


def sql(statement):
    p=subprocess.run(['/usr/bin/mysql','--defaults-extra-file='+ADMIN,'--batch','--skip-column-names',
                      '--raw','--silent','-D','orderguard_stage3'],input=statement,
                     capture_output=True,text=True,timeout=30,check=False,env=ENV)
    require(p.returncode==0,'MySQL operation failed')
    return p.stdout.strip()


def index_visibility():
    out=sql("SELECT SEQ_IN_INDEX,COLUMN_NAME,IS_VISIBLE FROM information_schema.statistics "
            "WHERE TABLE_SCHEMA='orderguard_stage3' AND TABLE_NAME='orders' "
            "AND INDEX_NAME='idx_merchant_status_created' ORDER BY SEQ_IN_INDEX;")
    rows=[line.split('\t') for line in out.splitlines()]
    require(len(rows)==3,'index definition changed')
    for index,(row,column) in enumerate(zip(rows,('merchant_id','order_status','created_at')),1):
        require(len(row)==3 and row[:2]==[str(index),column] and row[2] in ('YES','NO'),'index definition changed')
    values={row[2] for row in rows}; require(len(values)==1,'inconsistent index visibility')
    return values.pop()


def recover(rid):
    require(isinstance(rid,str) and re.fullmatch(r'[0-9a-f]{24}',rid),'invalid run id')
    guard(); digest=helper_digest()
    st=BASE.lstat(); require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,'unsafe state directory')
    fd=os.open(BASE/'m01.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd); require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
                                  stat.S_IMODE(st.st_mode)==0o600,'unsafe lock')
        deadline=time.monotonic()+30
        while True:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); break
            except BlockingIOError:
                require(time.monotonic()<deadline,'lock timed out'); time.sleep(.25)
        if not os.path.lexists(BASE/'state.json'): return
        boot=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        state=read_owned(rid,digest,boot)
        if state is None: return
        totals=sql('SELECT (SELECT COUNT(*) FROM orders),(SELECT COUNT(*) FROM orderguard.orders),'
                   '(SELECT COUNT(*) FROM orders WHERE merchant_id=88),@@GLOBAL.local_infile;')
        require(totals.split('\t')==['500000','5','25000','0'],'database baseline changed')
        if index_visibility()=='NO':
            sql('SET SESSION lock_wait_timeout=10; ALTER TABLE orders ALTER INDEX idx_merchant_status_created VISIBLE;')
        require(index_visibility()=='YES','index recovery not confirmed')
        print('M01 watchdog restored owned index visibility; state preserved')
    finally: os.close(fd)


if __name__=='__main__':
    try:
        require(len(sys.argv)==2,'expected run id'); recover(sys.argv[1])
    except (Refused,OSError,ValueError,subprocess.SubprocessError) as exc:
        print('M01 watchdog refused:',exc,file=sys.stderr); sys.exit(2)
