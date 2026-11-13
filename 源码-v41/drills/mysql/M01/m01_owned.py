#!/usr/bin/env python3
"""Run-ID-bound M01 controller for the isolated lab; candidate only."""
import argparse
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
import m01_core as c

HELPER=Path('/usr/local/libexec/opsdrill/m01/m01_watchdog.py')
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}
SECONDS=180


def require(value,message):
    if not value: raise c.Error(message,3)


def command(*args):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=15,check=False,env=ENV)
    if p.returncode: raise c.Error('system command failed',2)
    return p.stdout


def helper_digest():
    for p in (HELPER,*HELPER.parents):
        st=p.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,'unsafe watchdog path')
        if p!=HELPER: require(stat.S_ISDIR(st.st_mode),'unsafe watchdog parent')
    fd=os.open(HELPER,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and st.st_size<=1048576,
                'unsafe watchdog helper')
        return hashlib.sha256(f.read()).hexdigest()


def properties(unit,names):
    output=command('/usr/bin/systemctl','show',unit,*('--property='+n for n in names))
    result={}
    for line in output.splitlines():
        key,sep,value=line.partition('='); require(sep and key not in result,'invalid systemd response'); result[key]=value
    require('LoadState' in result,'missing systemd state')
    if set(result)!=set(names):
        require(result['LoadState']=='not-found','missing systemd properties')
        require(command('/usr/bin/systemctl','show',unit,'--property=LoadState').strip()=='LoadState=not-found',
                'unit changed during inspection')
    return result


def read_owned(rid=None,allow_reboot=False):
    state=c.read_state()
    if state is None: return None
    value=state.get('run_id')
    require(state.get('version')==2 and isinstance(value,str) and re.fullmatch(r'[0-9a-f]{24}',value),
            'state is not an owned M01 attempt')
    require(rid is None or value==rid,'M01 run id mismatch')
    require(state.get('timer')=='opsdrill-m01-recover-'+value+'.timer' and
            state.get('helper_sha256')==helper_digest() and type(state.get('armed_ns')) is int and
            isinstance(state.get('boot_id'),str),'M01 ownership mismatch')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if state['boot_id']!=boot:
        require(allow_reboot,'M01 boot changed')
        timer,service=units(state)
        require(timer.get('LoadState')==service.get('LoadState')=='not-found','old watchdog still present')
    return state


def units(state):
    rid=state['run_id']; timer=state['timer']; service=timer[:-6]+'.service'
    t=properties(timer,('Id','LoadState','ActiveState','SubState','Triggers','Transient','FragmentPath'))
    s=properties(service,('Id','LoadState','ActiveState','Transient','FragmentPath','ExecStart','User'))
    if s.get('LoadState')!='not-found':
        expected='argv[]=/usr/bin/python3 -I -B '+str(HELPER)+' '+rid+' ;'
        require(s.get('Id')==service and s.get('LoadState')=='loaded' and s.get('Transient')=='yes' and
                s.get('FragmentPath')=='/run/systemd/transient/'+service and s.get('User')=='root' and
                'path=/usr/bin/python3 ;' in s.get('ExecStart','') and expected in s.get('ExecStart',''),
                'watchdog service identity changed')
    if t.get('LoadState')!='not-found':
        require(t.get('Id')==timer and t.get('LoadState')=='loaded' and t.get('Triggers')==service and
                t.get('Transient')=='yes' and t.get('FragmentPath')=='/run/systemd/transient/'+timer,
                'watchdog timer identity changed')
    return t,s


def verify_armed(state):
    timer,service=units(state)
    require(timer.get('LoadState')=='loaded' and timer.get('ActiveState')=='active' and
            timer.get('SubState')=='waiting' and service.get('LoadState')=='loaded',
            'watchdog is not armed')
    age=time.monotonic_ns()-state['armed_ns']
    require(0<=age<=(SECONDS-60)*1_000_000_000,'watchdog window too short')


def disarm(state):
    timer,service=units(state)
    if service.get('LoadState')!='not-found':
        require(service.get('ActiveState') in ('inactive','failed'),'watchdog service running')
    if timer.get('LoadState')!='not-found':
        command('/usr/bin/systemctl','stop',state['timer'])
        _,service=units(state)
        if service.get('LoadState')!='not-found':
            require(service.get('ActiveState') in ('inactive','failed'),'watchdog service started during reset')


def start():
    c.baseline()
    require(c.read_state() is None,'existing M01 state')
    require(c.index_rows()=='YES' and c.expected_plan()==c.INDEX,'index baseline unhealthy')
    rid=secrets.token_hex(12); timer='opsdrill-m01-recover-'+rid+'.timer'
    require(properties(timer,('LoadState',)).get('LoadState')=='not-found','timer already exists')
    state={'id':'M01','version':2,'run_id':rid,'globals':c.globals_read(),'timer':timer,
           'helper_sha256':helper_digest(),'armed_ns':time.monotonic_ns(),
           'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    c.write_state(state)
    try:
        command('/usr/bin/systemd-run','--unit='+timer[:-6],'--on-active='+str(SECONDS)+'s',
                '--timer-property=AccuracySec=1s','--service-type=exec','--property=User=root',
                '/usr/bin/python3','-I','-B',str(HELPER),rid)
        verify_armed(state)
    except Exception:
        try:
            require(read_owned(rid)==state and c.index_rows()=='YES' and c.expected_plan()==c.INDEX and
                    c.globals_read()==state['globals'],'pre-injection baseline changed')
            disarm(state); c.STATE.unlink()
        except Exception:
            print('M01 pre-injection cleanup refused; state preserved',file=sys.stderr)
        raise
    c.visibility('INVISIBLE')
    require(c.index_rows()=='NO' and c.expected_plan()!=c.INDEX,'fault verification failed')
    require(c.globals_read()==state['globals'],'global settings changed externally')
    print(json.dumps({'receipt':'M01_INDEX_OWNER_V1','run_id':rid,'timer':timer}))


def restore(state):
    c.baseline()
    if c.index_rows()=='NO': c.visibility('VISIBLE')
    require(c.index_rows()=='YES' and c.expected_plan()==c.INDEX,'index recovery not confirmed')
    require(c.globals_read()==state['globals'],'global settings drift; inspect manually')


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('action',choices=('start','verify-owner','check','resolve','reset','inspect-clean'))
    parser.add_argument('run_id',nargs='?'); args=parser.parse_args()
    require((args.action in ('start','inspect-clean') and args.run_id is None) or
            (args.action not in ('start','inspect-clean') and isinstance(args.run_id,str) and re.fullmatch(r'[0-9a-f]{24}',args.run_id)),
            'invalid run id')
    c.safety(); c.require_dir(); fd=c.acquire_lock()
    try:
        if args.action=='start': start(); return 0
        if args.action=='inspect-clean':
            require(c.read_state() is None,'M01 state exists')
            require(not command('/usr/bin/systemctl','list-units','--all','--plain','--no-legend','opsdrill-m01-recover-*').strip(),
                    'M01 watchdog unit remains')
            require(c.check()==0,'M01 baseline unhealthy'); print('M01 clean'); return 0
        state=read_owned(args.run_id,allow_reboot=args.action=='reset')
        if state is None:
            if args.action=='reset': require(c.check()==0,'M01 baseline unhealthy'); return 0
            raise c.Error('no owned M01 state',3)
        if args.action=='verify-owner':
            verify_armed(state)
            require(c.index_rows()=='NO' and c.expected_plan()!=c.INDEX,'fault identity not verified')
            print('M01 owner verified'); return 0
        if args.action=='check': return c.check()
        if args.action=='resolve': restore(state); return 0
        restore(state); disarm(state); c.STATE.unlink(); print('M01 reset complete'); return 0
    finally: os.close(fd)


if __name__=='__main__':
    try: sys.exit(main())
    except c.Error as exc:
        print('M01 refused:',exc,file=sys.stderr); sys.exit(exc.code)
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        print('M01 operation failed:',type(exc).__name__,file=sys.stderr); sys.exit(2)
