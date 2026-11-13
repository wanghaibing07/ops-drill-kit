"""Arm an independent L02 stop timer before fault injection (candidate only).

Caller must hold the protected journal lock. No service or config is changed.
This module is not wired into start and has not been deployed.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from l02_policy import require
from l02_linux_inspect import secure_marker

HELPER=Path('/usr/local/libexec/opsdrill/l02-recovery-v2/l02_watchdog_helper.py')
PYTHON='/usr/bin/python3'
SECONDS=180
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}


def command(*args,check=True):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,env=ENV,timeout=15,check=False)
    require(not check or result.returncode==0,'system command failed')
    return result


def helper_digest():
    for path in (HELPER,*HELPER.parents):
        st=path.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,'unsafe helper path')
        if path!=HELPER: require(stat.S_ISDIR(st.st_mode),'unsafe helper parent')
    fd=os.open(HELPER,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
                not st.st_mode & 0o022 and st.st_size<=1024*1024,'unsafe helper')
        with os.fdopen(fd,'rb') as f:
            fd=-1; return hashlib.sha256(f.read()).hexdigest()
    finally:
        if fd>=0: os.close(fd)


def properties(unit,names):
    out=command('/usr/bin/systemctl','show',unit,*('--property='+n for n in names)).stdout
    result={}
    for line in out.splitlines():
        key,sep,value=line.partition('=')
        require(sep and key not in result,'invalid systemd properties')
        result[key]=value
    require('LoadState' in result,'missing systemd state')
    if set(result)!=set(names):
        require(result['LoadState']=='not-found','incomplete systemd properties')
        confirm=command('/usr/bin/systemctl','show',unit,'--property=LoadState').stdout.strip()
        require(confirm=='LoadState=not-found','unit changed during inspection')
    return result


def verify_armed(state):
    rid=state.get('run_id'); receipt=state.get('watchdog')
    require(isinstance(rid,str) and re.fullmatch(r'[0-9a-f]{24}',rid),'invalid run id')
    require(isinstance(receipt,dict) and receipt.get('timer')=='opsdrill-l02-recover-'+rid+'.timer' and
            receipt.get('helper_sha256')==helper_digest() and type(receipt.get('armed_ns')) is int,'invalid watchdog receipt')
    name=receipt['timer']; service=name[:-6]+'.service'
    timer=properties(name,('Id','LoadState','ActiveState','SubState','Triggers','Transient','FragmentPath'))
    require(timer.get('Id')==name and timer.get('LoadState')=='loaded' and timer.get('ActiveState')=='active' and
            timer.get('SubState')=='waiting' and timer.get('Triggers')==service and timer.get('Transient')=='yes' and
            timer.get('FragmentPath')=='/run/systemd/transient/'+name,'watchdog timer identity changed')
    props=properties(service,('Id','LoadState','Transient','FragmentPath','ExecStart','User'))
    expected='argv[]='+PYTHON+' -I '+str(HELPER)+' '+rid+' ;'
    require(props.get('Id')==service and props.get('LoadState')=='loaded' and props.get('Transient')=='yes' and
            props.get('FragmentPath')=='/run/systemd/transient/'+service and props.get('User')=='root' and
            'path='+PYTHON+' ;' in props.get('ExecStart','') and expected in props.get('ExecStart',''),
            'watchdog service identity changed')
    age=time.monotonic_ns()-receipt['armed_ns']
    require(0<=age<=(SECONDS-60)*1_000_000_000,'watchdog window too short')
    return True


def cancel_owned(state):
    """Stop only the recorded timer; an active helper makes reset retry later."""
    rid=state.get('run_id'); receipt=state.get('watchdog')
    require(isinstance(rid,str) and re.fullmatch(r'[0-9a-f]{24}',rid),'invalid run id')
    require(isinstance(receipt,dict) and receipt.get('timer')=='opsdrill-l02-recover-'+rid+'.timer' and
            receipt.get('helper_sha256')==helper_digest(),'invalid watchdog receipt')
    timer=receipt['timer']; service=timer[:-6]+'.service'
    timer_fields=('Id','LoadState','ActiveState','SubState','Triggers','Transient','FragmentPath')
    service_fields=('Id','LoadState','ActiveState','Transient','FragmentPath','ExecStart','User')
    def service_identity(props):
        if props.get('LoadState')=='not-found': return
        expected='argv[]='+PYTHON+' -I '+str(HELPER)+' '+rid+' ;'
        require(props.get('Id')==service and props.get('LoadState')=='loaded' and props.get('Transient')=='yes' and
                props.get('FragmentPath')=='/run/systemd/transient/'+service and props.get('User')=='root' and
                'path='+PYTHON+' ;' in props.get('ExecStart','') and expected in props.get('ExecStart',''),
                'watchdog service identity changed')
        require(props.get('ActiveState') in ('inactive','failed'),'watchdog service is still running')
    t=properties(timer,timer_fields); s=properties(service,service_fields)
    service_identity(s)
    if t.get('LoadState')=='not-found': return True
    require(t.get('Id')==timer and t.get('LoadState')=='loaded' and t.get('Triggers')==service and
            t.get('Transient')=='yes' and t.get('FragmentPath')=='/run/systemd/transient/'+timer,
            'watchdog timer identity changed')
    command('/usr/bin/systemctl','stop',timer)
    service_identity(properties(service,service_fields))
    return True


def arm(journal,state):
    """Persist timer intent first, then arm and verify; caller holds lock."""
    rid=state.get('run_id')
    require(os.geteuid()==0 and isinstance(rid,str) and re.fullmatch(r'[0-9a-f]{24}',rid),'invalid run')
    secure_marker()
    require(command('/usr/bin/systemd-detect-virt','--vm').stdout.strip()=='vmware','VMware required')
    require(command('/usr/sbin/getenforce').stdout.strip()=='Enforcing','SELinux not Enforcing')
    require(state.get('version')==1 and state.get('phase')=='PREPARED' and state.get('kind')=='config-port-v1',
            'not a prepared L02 run')
    require(state.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'boot changed')
    require('watchdog' not in state,'watchdog already recorded')
    timer='opsdrill-l02-recover-'+rid+'.timer'
    require(properties(timer,('LoadState',)).get('LoadState')=='not-found','timer already exists')
    unit='opsdrill-l02-'+rid+'.service'
    require(properties(unit,('LoadState',)).get('LoadState')=='not-found','service already exists')
    receipt={'timer':timer,'helper_sha256':helper_digest(),'armed_ns':time.monotonic_ns()}
    updated=dict(state); updated['watchdog']=receipt
    journal.save(rid,updated)
    command('/usr/bin/systemd-run','--unit='+timer[:-6],'--on-active='+str(SECONDS)+'s',
            '--timer-property=AccuracySec=1s','--service-type=exec','--property=User=root',
            PYTHON,'-I',str(HELPER),rid)
    verify_armed(updated)
    return updated
