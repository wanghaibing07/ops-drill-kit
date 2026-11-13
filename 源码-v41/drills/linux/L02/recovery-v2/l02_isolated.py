#!/usr/bin/env python3
"""Experimental isolated transient nginx controller, not an L02 judge.

No semanage mutations; no system nginx control. Do not deploy without review.
"""
import argparse
import contextlib
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
from l02_policy import Refused, require
from l02_linux_inspect import inspect

ROOT=Path('/etc/nginx/opsdrill-l02-isolated')
RID=re.compile(r'^[0-9a-f]{24}$')
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}


def command(*args, check=True):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                     env=ENV,text=True,timeout=30,check=False)
    if check: require(p.returncode==0,'system command failed: '+Path(args[0]).name)
    return p


def root_directory():
    # The private config tree is not included by the system nginx config.
    for parent in (Path('/'),Path('/etc'),Path('/etc/nginx')):
        st=parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,'unsafe config parent')
    try: os.mkdir(ROOT,0o700)
    except FileExistsError: pass
    fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    st=os.fstat(fd)
    require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,'unsafe state directory')
    return fd

@contextlib.contextmanager
def locked():
    dfd=root_directory()
    try:
        fd=os.open('.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dfd)
        try:
            st=os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,'unsafe lock')
            fcntl.flock(fd,fcntl.LOCK_EX)
            yield dfd
        finally: os.close(fd)
    finally: os.close(dfd)


def write_new(dfd,name,data,mode=0o600):
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode,dir_fd=dfd)
    try:
        os.fchmod(fd,mode)
        view=memoryview(data)
        while view:
            n=os.write(fd,view); require(n>0,'write failed'); view=view[n:]
        os.fsync(fd)
    finally: os.close(fd)
    os.fsync(dfd)


def read_secure(dfd,name):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dfd)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=8192,'unsafe run file')
        data=os.read(fd,8193); require(len(data)==st.st_size,'run file changed')
        return data
    finally: os.close(fd)


def run_fd(dfd,rid):
    require(isinstance(rid,str) and RID.fullmatch(rid),'invalid run id')
    fd=os.open(rid,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
    st=os.fstat(fd)
    require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,'unsafe run directory')
    return fd


def config_for(rid,port):
    require(RID.fullmatch(rid) and type(port) is int and 1024<=port<=65535,'invalid config identity')
    return ('pid /run/opsdrill-l02-'+rid+'.pid;\nerror_log stderr notice;\n'
            'events { worker_connections 16; }\nhttp { access_log off; '
            'server { listen 127.0.0.1:'+str(port)+'; location = /healthz { return 200 "l02-isolated\\n"; } } }\n').encode()


def expected_exec(rid):
    return '/usr/sbin/nginx -p '+str(ROOT/rid)+'/ -c nginx.conf -g daemon off;'


def properties(rid):
    unit='opsdrill-l02-'+rid+'.service'
    p=command('/usr/bin/systemctl','show',unit,'--no-pager','--property=Id,LoadState,FragmentPath,ExecStart,ActiveState,ControlGroup,Type,User,DropInPaths,RuntimeMaxUSec,Description',check=False)
    require(p.returncode==0,'cannot inspect transient unit')
    result={}
    for line in p.stdout.splitlines():
        if '=' in line:
            key,value=line.split('=',1); require(key not in result,'duplicate unit property'); result[key]=value
    return result


def verify_unit(rid,p,launch_token=None):
    unit='opsdrill-l02-'+rid+'.service'
    if p.get('LoadState')=='not-found': return False
    require(p.get('Id')==unit and p.get('LoadState')=='loaded' and p.get('FragmentPath')=='/run/systemd/transient/'+unit and
            p.get('Type')=='exec' and p.get('User','') in ('','root') and p.get('DropInPaths','')=='' and
            p.get('RuntimeMaxUSec') in ('2min','120s'), 'unit identity mismatch')
    raw=p.get('ExecStart','')
    require('path=/usr/sbin/nginx ;' in raw and ('argv[]='+expected_exec(rid)+' ;') in raw,'unit command mismatch')
    require(p.get('ControlGroup','') in ('','/system.slice/'+unit),'unit cgroup mismatch')
    if launch_token is not None:
        require(isinstance(launch_token,str) and re.fullmatch(r'[0-9a-f]{32}',launch_token) and
                p.get('Description')=='opsdrill-l02-launch-'+rid+'-'+launch_token,'unit launch identity mismatch')
    return True


def state_and_config(fd,rid):
    state=json.loads(read_secure(fd,'state.json'))
    require(isinstance(state,dict) and set(state)=={'run_id','port','sha256'} and state['run_id']==rid,'bad state')
    config=config_for(rid,state['port'])
    require(state['sha256']==hashlib.sha256(config).hexdigest() and read_secure(fd,'nginx.conf')==config,'config changed')
    return state


def start(port,rid=None,before_spawn=None,launch_token=None):
    info=inspect(port)
    require(info['effective_listed_type']=='unreserved_port_t' and info['local_listed_type'] is None and not info['tcp_socket_present'],'port policy changed or occupied')
    rid=rid or secrets.token_hex(12)
    require(isinstance(rid,str) and RID.fullmatch(rid),'invalid run id')
    require(launch_token is None or (isinstance(launch_token,str) and re.fullmatch(r'[0-9a-f]{32}',launch_token)),
            'invalid launch identity')
    config=config_for(rid,port)
    with locked() as dfd:
        os.mkdir(rid,0o700,dir_fd=dfd); os.fsync(dfd)
        fd=run_fd(dfd,rid)
        try:
            state={'run_id':rid,'port':port,'sha256':hashlib.sha256(config).hexdigest()}
            write_new(fd,'nginx.conf',config)
            write_new(fd,'state.json',(json.dumps(state,sort_keys=True)+'\n').encode())
            # Give only the owned private tree its policy-defined label.
            command('/usr/sbin/restorecon','-R',str(ROOT/rid))
            # Prevent accidental adoption of an existing service name.
            require(not verify_unit(rid,properties(rid)),'unit already exists')
            if before_spawn is not None:
                require(callable(before_spawn),'invalid pre-start guard')
                before_spawn(rid)
            # The systemd manager itself stops the unit after 120s; on any failure
            # state remains for inspection. This is not a durable cleanup watchdog.
            marker=('--property=Description=opsdrill-l02-launch-'+rid+'-'+launch_token,) if launch_token else ()
            command('/usr/bin/systemd-run','--unit=opsdrill-l02-'+rid,'--service-type=exec',
                    '--property=RuntimeMaxSec=120s','--property=TimeoutStopSec=10s','--property=Restart=no',*marker,
                    '/usr/sbin/nginx','-p',str(ROOT/rid)+'/','-c','nginx.conf','-g','daemon off;')
            require(verify_unit(rid,properties(rid),launch_token),'created unit missing')
            return rid
        finally: os.close(fd)


def cleanup(rid):
    # inspect also enforces root/VM/lab/Enforcing, without mutating policy.
    with locked() as dfd:
        try: fd=run_fd(dfd,rid)
        except FileNotFoundError: return
        try:
            state_and_config(fd,rid)
            p=properties(rid)
            if verify_unit(rid,p) and p.get('ActiveState') not in ('inactive','failed'):
                command('/usr/bin/systemctl','stop','opsdrill-l02-'+rid+'.service')
            p=properties(rid)
            if verify_unit(rid,p):
                require(p.get('ActiveState') in ('inactive','failed') and not p.get('ControlGroup'), 'service still running')
            # Retain state/config as evidence; no deletion of unknown nginx files.
        finally: os.close(fd)


def main():
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest='action',required=True)
    a=sub.add_parser('start'); a.add_argument('port',type=int)
    b=sub.add_parser('cleanup'); b.add_argument('run_id')
    args=parser.parse_args()
    if args.action=='start': print(start(args.port))
    else:
        # Guard without relying on state supplied port.
        from l02_linux_inspect import secure_marker
        require(os.geteuid()==0,'root required'); secure_marker()
        require(command('/usr/bin/systemd-detect-virt','--vm').stdout.strip()=='vmware','not VMware')
        require(command('/usr/sbin/getenforce').stdout.strip()=='Enforcing','SELinux not Enforcing')
        cleanup(args.run_id)

if __name__=='__main__':
    try: main()
    except (Refused,OSError,ValueError,KeyError,subprocess.SubprocessError) as e:
        print('l02-isolated: '+str(e),file=sys.stderr); sys.exit(2)
