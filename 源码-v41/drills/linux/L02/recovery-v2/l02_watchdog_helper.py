#!/usr/bin/env python3
"""Conservatively stop one recorded L02 transient Nginx; preserve state.

This standalone root helper is a candidate, not installed or wired into L02.
It never changes SELinux policy, system Nginx, or any configuration file.
Unknown ownership fails closed; a later explicit reset must finish cleanup.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

HELPER=Path('/usr/local/libexec/opsdrill/l02-recovery-v2/l02_watchdog_helper.py')
BASE=Path('/var/lib/opsdrill/l02-journal')
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}


class Refused(Exception): pass


def require(value,message):
    if not value: raise Refused(message)


def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'duplicate state key')
        result[key]=value
    return result


def valid_id(rid): return isinstance(rid,str) and re.fullmatch(r'[0-9a-f]{24}',rid) is not None


def validate_state(state,rid,boot,helper_digest):
    require(valid_id(rid) and isinstance(state,dict),'invalid run')
    require(state.get('version')==1 and state.get('run_id')==rid and state.get('boot_id')==boot and
            state.get('kind')=='config-port-v1','state or boot mismatch')
    require(state.get('phase') in ('PREPARED','FAULT','REPAIR_INTENT','REPAIRED','RESET_INTENT','NEEDS_REVIEW'),
            'invalid state phase')
    receipt=state.get('watchdog')
    require(isinstance(receipt,dict) and receipt.get('helper_sha256')==helper_digest and
            receipt.get('timer')=='opsdrill-l02-recover-'+rid+'.timer','invalid watchdog receipt')
    invocation=state.get('invocation')
    require(invocation is None or (isinstance(invocation,str) and re.fullmatch(r'[0-9a-f]{32}',invocation) and invocation!='0'*32),
            'invalid invocation')
    return invocation


def validate_service(rid,invocation,props,launch_token=None):
    name='opsdrill-l02-'+rid+'.service'
    require(props.get('Id')==name and props.get('LoadState') in ('loaded','not-found'),'invalid service')
    if props['LoadState']=='not-found': return False
    prefix='/etc/nginx/opsdrill-l02-isolated/'+rid+'/'
    expected='argv[]=/usr/sbin/nginx -p '+prefix+' -c nginx.conf -g daemon off; ;'
    require(invocation is not None and props.get('InvocationID')==invocation and
            props.get('Transient')=='yes' and props.get('FragmentPath')=='/run/systemd/transient/'+name and
            props.get('Type')=='exec' and props.get('User','') in ('','root') and props.get('DropInPaths','')=='' and
            'path=/usr/sbin/nginx ;' in props.get('ExecStart','') and expected in props.get('ExecStart',''),
            'service identity changed')
    group=props.get('ControlGroup','')
    require(group in ('','/system.slice/'+name),'service cgroup changed')
    if launch_token is not None:
        require(isinstance(launch_token,str) and re.fullmatch(r'[0-9a-f]{32}',launch_token) and
                props.get('Description')=='opsdrill-l02-launch-'+rid+'-'+launch_token and
                props.get('Restart')=='no' and props.get('NRestarts')=='0' and
                props.get('RuntimeMaxUSec') in ('2min','120s') and
                props.get('ExecStart','').count('path=')==1 and props.get('ExecStart','').count('argv[]=')==1,
                'service launch identity changed')
    require(props.get('ActiveState') in ('active','activating','inactive','failed','deactivating'),
            'unknown service state')
    if props.get('ActiveState') in ('active','activating'):
        require(group=='/system.slice/'+name,'active service has no owned cgroup')
    return True


def command(*args):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,env=ENV,timeout=15,check=False)
    require(result.returncode==0,'system command failed')
    return result.stdout


def properties(rid):
    unit='opsdrill-l02-'+rid+'.service'
    names=('Id','LoadState','ActiveState','Transient','FragmentPath','Type','User','DropInPaths',
           'InvocationID','ExecStart','ControlGroup','Description','Restart','NRestarts','RuntimeMaxUSec')
    output=command('/usr/bin/systemctl','show',unit,*('--property='+name for name in names))
    rows={}
    for line in output.splitlines():
        key,sep,value=line.partition('=')
        require(sep and key not in rows,'invalid systemd response')
        rows[key]=value
    require('LoadState' in rows and 'Id' in rows,'missing systemd identity')
    if rows['LoadState']=='loaded': require(set(names)==set(rows),'missing systemd properties')
    if rows['LoadState']=='not-found':
        require(command('/usr/bin/systemctl','show',unit,'--property=LoadState').strip()=='LoadState=not-found',
                'service changed during inspection')
    return rows


def secure_self():
    require(Path(os.path.abspath(__file__))==HELPER,'helper path mismatch')
    for path in (HELPER,*HELPER.parents):
        st=path.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,'unsafe helper path')
        if path!=HELPER: require(stat.S_ISDIR(st.st_mode),'unsafe helper parent')
    fd=os.open(HELPER,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and st.st_size<=1024*1024,'unsafe helper')
        with os.fdopen(fd,'rb') as stream:
            fd=-1
            return hashlib.sha256(stream.read()).hexdigest()
    finally:
        if fd>=0: os.close(fd)


def guard():
    require(os.geteuid()==0,'root required')
    require(command('/usr/bin/systemd-detect-virt','--vm').strip()=='vmware','VMware required')
    fd=os.open('/etc/opsdrill-lab',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
                not st.st_mode & 0o022 and st.st_size<=64 and os.read(fd,65).strip()==b'ops-drill-kit','unsafe marker')
    finally: os.close(fd)


def journal_directory():
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for component in ('var','lib','opsdrill','l02-journal'):
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            st=os.fstat(child)
            if not (stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022):
                os.close(child); raise Refused('unsafe journal directory')
            os.close(fd); fd=child
        require(stat.S_IMODE(os.fstat(fd).st_mode)==0o700,'unsafe journal mode')
        return fd
    except BaseException:
        os.close(fd); raise


def acquire(dfd):
    fd=os.open('.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dfd)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
                stat.S_IMODE(st.st_mode)==0o600,'unsafe journal lock')
        deadline=time.monotonic()+30
        while True:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); return fd
            except BlockingIOError:
                require(time.monotonic()<deadline,'journal lock timed out')
                time.sleep(.25)
    except BaseException:
        os.close(fd); raise


def read_state(dfd,rid):
    try: fd=os.open(rid+'.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dfd)
    except FileNotFoundError: return None
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
                stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=32768,'unsafe state file')
        data=os.read(fd,32769)
        require(len(data)==st.st_size,'state changed during read')
        return json.loads(data,object_pairs_hook=unique)
    finally: os.close(fd)


def save_state(dfd,rid,state):
    data=(json.dumps(state,sort_keys=True,separators=(',',':'))+'\n').encode()
    require(len(data)<=32768,'state too large')
    name='.watchdog-'+secrets.token_hex(16)
    fd=os.open(name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dfd)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(name,rid+'.json',src_dir_fd=dfd,dst_dir_fd=dfd)
        os.fsync(dfd)
    finally:
        try: os.unlink(name,dir_fd=dfd)
        except FileNotFoundError: pass


def recover(rid):
    require(valid_id(rid),'invalid run id')
    guard(); helper_digest=secure_self(); boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    dfd=journal_directory()
    try:
        lock=acquire(dfd)
        try:
            state=read_state(dfd,rid)
            if state is None: return
            invocation=validate_state(state,rid,boot,helper_digest)
            require(state.get('watchdog_status')!='IDENTITY_UNVERIFIED','identity requires manual review')
            token=None
            if 'launch_intent' in state or state.get('watchdog_status')=='OWNED_PREWRITE_VERIFIED':
                intent=state.get('launch_intent')
                require(isinstance(intent,dict) and set(intent)=={'version','token'} and intent['version']==1 and
                        isinstance(intent['token'],str) and re.fullmatch(r'[0-9a-f]{32}',intent['token']),
                        'launch intent unavailable')
                token=intent['token']
            props=properties(rid)
            if invocation is None and props.get('LoadState') == 'loaded':
                intent=state.get('launch_intent')
                try:
                    require(state['phase']=='PREPARED' and isinstance(intent,dict) and
                            set(intent)=={'version','token'} and intent['version']==1 and
                            isinstance(intent['token'],str) and re.fullmatch(r'[0-9a-f]{32}',intent['token']),
                            'launch intent unavailable')
                    token=intent['token']
                    invocation=props.get('InvocationID')
                    require(isinstance(invocation,str) and re.fullmatch(r'[0-9a-f]{32}',invocation) and invocation!='0'*32,
                            'unit invocation unavailable')
                    validate_service(rid,invocation,props,token)
                    # Bind recovery to the observed invocation before requesting stop.
                    state['invocation']=invocation
                    state['phase']='NEEDS_REVIEW'
                    state['watchdog_status']='OWNED_PREWRITE_VERIFIED'
                    save_state(dfd,rid,state)
                    props=properties(rid)
                    validate_service(rid,invocation,props,token)
                except Refused:
                    state['phase']='NEEDS_REVIEW'
                    state['watchdog_status']='IDENTITY_UNVERIFIED'
                    save_state(dfd,rid,state)
                    raise
            if validate_service(rid,invocation,props,token):
                if props['ActiveState'] not in ('inactive','failed'):
                    command('/usr/bin/systemctl','stop','opsdrill-l02-'+rid+'.service')
                    props=properties(rid)
                if validate_service(rid,invocation,props,token):
                    require(props['ActiveState'] in ('inactive','failed') and not props.get('ControlGroup'),
                            'owned service still running')
            state['phase']='NEEDS_REVIEW'
            state['watchdog_status']='STOPPED_OR_ABSENT'
            save_state(dfd,rid,state)
            print('L02 watchdog stopped owned service; state preserved')
        finally: os.close(lock)
    finally: os.close(dfd)


if __name__=='__main__':
    try:
        require(len(sys.argv)==2,'expected run id')
        recover(sys.argv[1])
    except (Refused,OSError,ValueError,subprocess.SubprocessError) as exc:
        print('L02 watchdog refused:',exc,file=sys.stderr)
        sys.exit(2)
