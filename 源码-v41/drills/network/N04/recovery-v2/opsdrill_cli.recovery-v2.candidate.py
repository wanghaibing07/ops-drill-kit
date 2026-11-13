#!/usr/bin/env python3
"""Explicitly registered drill commands with a conservative local state machine."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
STATE_ROOT = Path('/var/lib/opsdrill/cli')
EVENT_FILE = Path('/var/lib/opsdrill/events.jsonl')
REGISTRY = {'M01':'drills/mysql/M01', 'M02':'drills/mysql/M02', 'L01':'drills/linux/L01', 'L02':'drills/linux/L02', 'L03':'drills/linux/L03', 'L04':'drills/linux/L04', 'N03':'drills/network/N03', 'N02':'drills/network/N02', 'N01':'drills/network/N01', 'N04':'drills/network/N04'}
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')


class Refused(Exception):
    pass


def require_root():
    if os.geteuid()!=0: raise Refused('root required for state-changing actions')


def safe_dir():
    parent = STATE_ROOT.parent
    if parent.is_symlink() or not parent.is_dir(): raise Refused('state parent missing or unsafe')
    pst=parent.stat()
    if pst.st_uid != 0 or pst.st_mode & 0o022: raise Refused('unsafe state parent')
    try: STATE_ROOT.mkdir(mode=0o700)
    except FileExistsError: pass
    st=STATE_ROOT.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o700:
        raise Refused('unsafe state directory')


def open_lock(name):
    fd=os.open(STATE_ROOT/name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:
        os.close(fd); raise Refused('unsafe lock')
    try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd); raise Refused('another operation is running')
    return fd


def state_path(drill): return STATE_ROOT/(drill+'.json')


def read_state(drill):
    try: fd=os.open(state_path(drill),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    except FileNotFoundError: return None
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>4096:
            raise Refused('unsafe state file')
        raw=os.read(fd,4097)
        obj=json.loads(raw,object_pairs_hook=unique_pairs) if drill=='N04' else json.loads(raw)
    finally: os.close(fd)
    if not isinstance(obj,dict) or obj.get('drill_id')!=drill or obj.get('phase') not in ('STARTING','ACTIVE','NEEDS_RESET'):
        raise Refused('invalid state')
    attempt=obj.get('attempt_id')
    if not isinstance(attempt,str) or not re.fullmatch(re.escape(drill)+r'-[0-9]{8}-[0-9]{6}',attempt):
        raise Refused('invalid attempt id')
    if drill=='L04' and obj.get('phase')=='ACTIVE':
        rid=obj.get('run_id')
        if (not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid)
                or obj.get('unit')!='opsdrill-l04-'+rid+'-fault.service'):
            raise Refused('invalid owned L04 identity')
    if obj.get('phase')=='ACTIVE' and drill=='L03':
        rid=obj.get('run_id'); unit=obj.get('unit')
        if not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid) or unit!='opsdrill-l03-'+rid+'.service':
            raise Refused('invalid owned L03 identity')
    if obj.get('phase')=='ACTIVE' and drill=='L01':
        rid=obj.get('run_id'); variant=obj.get('variant')
        if not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid) or variant not in ('inode','deleted-open'):
            raise Refused('invalid owned L01 identity')
        if variant=='deleted-open' and obj.get('unit')!='opsdrill-l01-deleted-'+rid+'.service':
            raise Refused('invalid owned L01 unit')
    if obj.get('phase')=='ACTIVE' and drill=='M01':
        rid=obj.get('run_id')
        if (not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid)
                or obj.get('timer')!='opsdrill-m01-recover-'+rid+'.timer'):
            raise Refused('invalid owned M01 identity')
    if obj.get('phase')=='ACTIVE' and drill=='L02':
        rid=obj.get('run_id')
        if (not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid)
                or obj.get('timer')!='opsdrill-l02-recover-'+rid+'.timer'):
            raise Refused('invalid owned L02 identity')
    if drill=='N04' and 'n04_version' in obj:
        if obj['n04_version']!='recovery-v2' or not isinstance(obj.get('run_id'),str) or not re.fullmatch(r'[0-9a-f]{24}',obj['run_id']):
            raise Refused('invalid N04 version or identity')
    if obj.get('phase') in ('ACTIVE','NEEDS_RESET') and drill=='N04' and 'run_id' in obj:
        rid=obj['run_id']
        if not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid):
            raise Refused('invalid owned N04 identity')
    if obj.get('phase')=='ACTIVE' and drill=='N04' and 'run_id' not in obj:
        raise Refused('missing owned N04 identity')
    if obj.get('phase')=='ACTIVE' and drill in ('N01','N02'):
        rid=obj.get('run_id')
        if not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid):
            raise Refused('invalid owned network drill identity')
    if obj.get('phase')=='ACTIVE' and drill=='N03':
        rid=obj.get('run_id')
        if (not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid) or obj.get('variant') not in ('502','504')
                or obj.get('timer')!='opsdrill-n03-recover-'+rid+'.timer'):
            raise Refused('invalid owned N03 identity')
    return obj


def write_state(drill,obj):
    fd,path=tempfile.mkstemp(prefix='.new-',dir=STATE_ROOT)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(obj,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(path,state_path(drill))
        dfd=os.open(STATE_ROOT,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(path): os.unlink(path)


def event(drill,attempt,kind,result,actor):
    obj={'drill_id':drill,'attempt_id':attempt,'event':kind,'result':result,
         'actor':actor,'ts':datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'boot_id':BOOT_ID.read_text(encoding='ascii').strip(),'monotonic_ns':time.monotonic_ns()}
    fd=os.open(EVENT_FILE,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:
            raise Refused('unsafe events file')
        fcntl.flock(fd,fcntl.LOCK_EX)
        data=(json.dumps(obj,sort_keys=True)+'\n').encode()
        view=memoryview(data)
        while view:
            written=os.write(fd,view)
            if written<=0: raise Refused('event write failed')
            view=view[written:]
        os.fsync(fd)
    finally: os.close(fd)


def secure_file(relative):
    path=PROJECT/relative
    for component in (path,*path.parents):
        if component==PROJECT: break
        if component.is_symlink(): raise Refused('symlink in project path')
    resolved=path.resolve(strict=True)
    if PROJECT not in resolved.parents or not resolved.is_file():
        raise Refused('unsafe drill script')
    return resolved


def script_path(drill,action):
    if drill not in REGISTRY or action not in ('inject','check','reset'):
        raise Refused('drill or action not registered')
    if drill=='L04': return Path('/usr/local/libexec/opsdrill/l04/controller.py')
    if drill=='N04': return Path('/usr/local/libexec/opsdrill/n04/n04_lifecycle.py')
    if drill=='N01': return n01_controller()
    return secure_file(REGISTRY[drill]+'/'+action+'.sh')


def invoke(drill,action,extra=(),capture=False,n04_version='legacy'):
    command=(l04_command('start' if action=='inject' else action,extra) if drill=='L04'
             else n04_command('start' if action=='inject' else action,extra,n04_version) if drill=='N04'
             else m01_command('start' if action=='inject' else action,extra) if drill=='M01'
             else l02_command('start' if action=='inject' else action,extra) if drill=='L02'
             else ['/usr/bin/python3',str(n01_controller()),'repair' if action=='resolve' else action,*extra] if drill=='N01'
             else ['/usr/bin/python3',str(n02_controller()),action,*extra] if drill=='N02'
             else ['/bin/bash',str(script_path(drill,action)),*extra])
    cp=subprocess.run(command,check=False,
                      capture_output=capture,text=capture)
    if capture: return cp
    return cp.returncode


def unique_pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise Refused('duplicate receipt field')
        result[key]=value
    return result


def l01_args(state):
    result=(state['variant'],state['run_id'])
    return result+(state['unit'],) if state['variant']=='deleted-open' else result


def l01_clean():
    path=secure_file(REGISTRY['L01']+'/clean.sh')
    return subprocess.run(['/bin/bash',str(path)],check=False).returncode


def n03_clean():
    path=secure_file(REGISTRY['N03']+'/n03_502.py')
    return subprocess.run(['/usr/bin/python3',str(path),'inspect-clean'],check=False).returncode


def n01_controller():
    path=Path('/usr/local/libexec/opsdrill/n01/n01.py')
    for part in (path,*path.parents):
        try: st=part.lstat()
        except OSError as exc: raise Refused('N01 controller missing or inaccessible') from exc
        if stat.S_ISLNK(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise Refused('N01 controller path is not root-controlled')
        if part != path and not stat.S_ISDIR(st.st_mode):
            raise Refused('N01 controller parent is not a directory')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o022 or st.st_size>1048576:
            raise Refused('unsafe N01 controller')
        with os.fdopen(fd,'rb') as stream:
            fd=-1
            digest=hashlib.sha256(stream.read(1048577)).hexdigest()
    finally:
        if fd>=0: os.close(fd)
    if digest!='96fc2a764a432d08658c4cd0d6521e5f1fb4fca2a7c98f166be753e3240a6ac8':
        raise Refused('N01 controller version mismatch')
    return path



def n02_controller():
    path=Path('/usr/local/libexec/opsdrill/n02/n02.py')
    for part in (path,*path.parents):
        try: st=part.lstat()
        except OSError as exc: raise Refused('N02 controller missing or inaccessible') from exc
        if stat.S_ISLNK(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise Refused('N02 controller path is not root-controlled')
        if part != path and not stat.S_ISDIR(st.st_mode):
            raise Refused('N02 controller parent is not a directory')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o022 or st.st_size>1048576:
            raise Refused('unsafe N02 controller')
        with os.fdopen(fd,'rb') as stream:
            fd=-1
            digest=hashlib.sha256(stream.read(1048577)).hexdigest()
    finally:
        if fd>=0: os.close(fd)
    if digest!='a22e59d0217ab059b6c32f985094f074d8d553a273c2d3a2cc4065360d3120dc':
        raise Refused('N02 controller version mismatch')
    return path


def n02_clean():
    return subprocess.run(['/usr/bin/python3',str(n02_controller()),'inspect-clean'],check=False).returncode


L02_MANIFEST = {'l02_audit.py': 'fbed2c8254298d2a1a949ba67445729934edf3ab81851d9b6f7c88878094683f', 'l02_cli.py': '5f98e65c4ebd988bf8d4cec3206fc9b6cd8ea8362c788119f7bf9002970e8d2d', 'l02_config_lifecycle.py': 'a0cd65197f4411340eba0a133096e477212f880e08729e9ad372c1faa905c4bc', 'l02_initialize.py': '70487c50033c5cfb0145b8392110915c19470b40ceeb932caae6573d40dc29a2', 'l02_isolated.py': '9261ead42dfff96672ed1beab6efff7e6330db3dcc7340f65138f7a2e4ce1a8f', 'l02_journal_avc.py': '9b1433956277e122134d536adab232b92f7589f6b4d27715c850518c923f1d8e', 'l02_linux_config.py': 'e20aa533d9151ca868c2c14ecc46f3914888f2a1cee7c5969bde95d9c6e66078', 'l02_linux_config_backend.py': 'b521fe01a23a6539a27810a92d48702079ae96321a41dd40f1518c4ff7a168ce', 'l02_linux_evidence.py': 'f1be95bdc198e346209aa8ac3e7b37260654b08080336fb61edf5b6d6ee12bcd', 'l02_linux_inspect.py': '6614d7e15b1d93ee9a14a2ddcdfa4809bc7bc5c92db3e2d559019fdb32e4c8f4', 'l02_linux_journal.py': '82ddac3719b4a550007bc4806bae15a9c66ee7af3e12a12524939a8dfc0c239b', 'l02_policy.py': '1f0256043cd16b373673c088740581fec810fa1db0d600fdcd91a256fa0b5445', 'l02_prepare.py': '365e218526f66c7a305572030184fe0e92132a45e3e30b4b71a1d17c2739200f', 'l02_watchdog_arm.py': '642841082d4970d6716346774998923c3b86ad4301d5c504a6c7f1fe0d4a3026', 'l02_watchdog_helper.py': '0556e8b476e8844eefcdfcf224c8c497b41237c2fd3a1d31de230df2defba474'}


def l02_command(action,extra=()):
    root=Path('/usr/local/libexec/opsdrill/l02')
    for part in (root,*root.parents):
        try: st=part.lstat()
        except OSError as exc: raise Refused('L02 installation missing or inaccessible') from exc
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise Refused('L02 installation path is not root-controlled')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if set(os.listdir(fd))!=set(L02_MANIFEST): raise Refused('unexpected L02 installation files')
        for name,expected in L02_MANIFEST.items():
            item=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            with os.fdopen(item,'rb') as stream:
                st=os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o022 or st.st_size>1048576:
                    raise Refused('unsafe L02 module')
                if hashlib.sha256(stream.read(1048577)).hexdigest()!=expected:
                    raise Refused('L02 module version mismatch')
    finally: os.close(fd)
    shim="import runpy,sys;sys.path.insert(0,'/usr/local/libexec/opsdrill/l02');runpy.run_path('/usr/local/libexec/opsdrill/l02/l02_cli.py',run_name='__main__')"
    return ['/usr/bin/python3','-I','-B','-c',shim,action,*extra]


def l02_clean():
    return subprocess.run(l02_command('inspect-clean'),check=False).returncode


N04_MANIFEST = {'n04.py': '9c843ec997e0ab0de2053f56d3ef8445dc054646c916170960f55b16970ba10b', 'n04_lifecycle.py': '3b66b415d5c93087bf200d0a48de95c3eb913d8aa656c58e22b6487881d4362b'}


N04_V2_MANIFEST = {'n04.py': 'abff5af4494643834afc3dc0320e43c0d0661a6081ef50c779fc786f05007573', 'n04_lifecycle.py': 'aae4b424880ab3fefcae2931712f34b44e92988060c4a98c6d8d55ba5c3227f3'}


def n04_command(action,extra=(),version='legacy'):
    if version not in ('legacy','recovery-v2'): raise Refused('unknown N04 version')
    root=Path('/usr/local/libexec/opsdrill/n04' if version=='legacy' else '/usr/local/libexec/opsdrill/n04-recovery-v2')
    selected_manifest=N04_MANIFEST if version=='legacy' else N04_V2_MANIFEST
    for part in (root,*root.parents):
        try: st=part.lstat()
        except OSError as exc: raise Refused('N04 installation missing or inaccessible') from exc
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise Refused('N04 installation path is not root-controlled')
    manifest=(json.dumps(selected_manifest,sort_keys=True)+'\n').encode('ascii')
    expected=dict(selected_manifest,**{'manifest.json':hashlib.sha256(manifest).hexdigest()})
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if set(os.listdir(fd))!=set(expected): raise Refused('unexpected N04 installation files')
        for name,digest in expected.items():
            item=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            with os.fdopen(item,'rb') as stream:
                st=os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o022 or st.st_size>1048576:
                    raise Refused('unsafe N04 module')
                if hashlib.sha256(stream.read(1048577)).hexdigest()!=digest:
                    raise Refused('N04 module version mismatch')
    finally: os.close(fd)
    return ['/usr/bin/python3','-I','-B',str(root/'n04_lifecycle.py'),action,*extra]


def n04_response(cp,rid,action):
    try: value=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
    except (TypeError,ValueError,Refused): raise Refused('invalid N04 response')
    if (not isinstance(value,dict) or value.get('run_id')!=rid or value.get('action')!=action
            or value.get('ok') is not True): raise Refused('invalid N04 response identity')
    return value


def n04_check_outcome(cp,rid):
    value=n04_response(cp,rid,'check'); result=value.get('result')
    if (not isinstance(result,dict) or result.get('event')!='check'
            or type(result.get('fault_proven')) is not bool or type(result.get('repaired')) is not bool
            or type(result.get('time_wait')) is not int or result['time_wait']<0
            or not isinstance(result.get('range'),list) or len(result['range'])!=2
            or any(type(x) is not int for x in result['range'])
            or not 1<=result['range'][0]<result['range'][1]<=65535):
        raise Refused('invalid N04 check evidence')
    fault=result['fault_proven']; repaired=result['repaired']
    if fault and (result['time_wait']<1 or result['range']!=[40000,40031]):
        raise Refused('inconsistent N04 fault evidence')
    if repaired and result['range'][1]-result['range'][0]+1<1024:
        raise Refused('inconsistent N04 recovery evidence')
    expected=0 if repaired and not fault else 1 if fault and not repaired else 2 if not fault and not repaired else None
    if expected is None or cp.returncode!=expected: raise Refused('inconsistent N04 check result')
    return expected


def n04_resolve_ok(cp,rid):
    value=n04_response(cp,rid,'resolve'); result=value.get('result')
    return (cp.returncode==0 and isinstance(result,dict) and result.get('event')=='repair'
            and result.get('range_restored') is True and result.get('reuse_passed') is True
            and type(result.get('requests_on_one_connection')) is int and result['requests_on_one_connection']==8)


def n04_reset_ok(cp,rid):
    value=n04_response(cp,rid,'reset'); result=value.get('result')
    if cp.returncode!=0 or value.get('service_stopped') is not True: return False
    if value.get('already_completed') is True:
        return result is None
    return isinstance(result,dict) and result.get('event')=='reset' and result.get('range_restored') is True


L04_MANIFEST = {'controller.py': '795ee1a568148b6c58975a90b18f9dcb67226d646dfce83a58220e045b61255a', 'service.py': 'e1c2b9ad03adf59f3af4052c931ebe08630c407c82e0ac90bfd1366a4b3cd9d0'}


def l04_command(action,extra=()):
    root=Path('/usr/local/libexec/opsdrill/l04')
    for part in (root,*root.parents):
        try: st=part.lstat()
        except OSError as exc: raise Refused('L04 installation missing or inaccessible') from exc
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise Refused('L04 installation path is not root-controlled')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        entries=set(os.listdir(fd))
        if not set(L04_MANIFEST)<=entries or entries-set(L04_MANIFEST)-{'runtime'}:
            raise Refused('unexpected L04 installation files')
        if 'runtime' in entries:
            st=os.stat('runtime',dir_fd=fd,follow_symlinks=False)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o700:
                raise Refused('unsafe L04 runtime directory')
        for name,expected in L04_MANIFEST.items():
            item=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            with os.fdopen(item,'rb') as stream:
                st=os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o022 or st.st_size>1048576:
                    raise Refused('unsafe L04 module')
                if hashlib.sha256(stream.read(1048577)).hexdigest()!=expected:
                    raise Refused('L04 module version mismatch')
    finally: os.close(fd)
    return ['/usr/bin/python3','-I','-B',str(root/'controller.py'),action,*extra]


def l04_receipt_path(rid):
    if not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid): raise Refused('invalid L04 run ID')
    return STATE_ROOT/('L04-done-'+rid+'.json')


def l04_receipt(rid):
    try: fd=os.open(l04_receipt_path(rid),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    except FileNotFoundError: return False
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>1024:
            raise Refused('unsafe L04 CLI completion receipt')
        value=json.loads(os.read(fd,1025),object_pairs_hook=unique_pairs)
        if value!={'receipt':'L04_CLI_DONE_V1','run_id':rid}: raise Refused('invalid L04 CLI completion receipt')
        return True
    finally: os.close(fd)


def l04_mark_done(rid):
    if l04_receipt(rid): return
    fd=os.open(l04_receipt_path(rid),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        data=json.dumps({'receipt':'L04_CLI_DONE_V1','run_id':rid},sort_keys=True).encode()
        with os.fdopen(fd,'wb') as f:
            fd=-1; f.write(data); f.flush(); os.fsync(f.fileno())
        dfd=os.open(STATE_ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if fd>=0: os.close(fd)


M01_MANIFEST = {'m01_core.py': 'a86235b38a7f26713b819832b42b2eb0b2d6b280b69e528d9e91b64dbc31747d', 'm01_owned.py': '8b40779dd53458876a32d8312714b071ce186e9788b878fb263dbafb99fbc79f', 'm01_watchdog.py': 'a546052e9bea13ff0c8c8781e9ea317ee788753503ff1d896639347aa07342df'}


def m01_command(action,extra=()):
    root=Path('/usr/local/libexec/opsdrill/m01')
    for part in (root,*root.parents):
        try: st=part.lstat()
        except OSError as exc: raise Refused('M01 installation missing or inaccessible') from exc
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise Refused('M01 installation path is not root-controlled')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if set(os.listdir(fd))!=set(M01_MANIFEST): raise Refused('unexpected M01 installation files')
        for name,expected in M01_MANIFEST.items():
            item=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            with os.fdopen(item,'rb') as stream:
                st=os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o022 or st.st_size>1048576:
                    raise Refused('unsafe M01 module')
                if hashlib.sha256(stream.read(1048577)).hexdigest()!=expected:
                    raise Refused('M01 module version mismatch')
    finally: os.close(fd)
    shim="import runpy,sys;sys.path.insert(0,'/usr/local/libexec/opsdrill/m01');runpy.run_path('/usr/local/libexec/opsdrill/m01/m01_owned.py',run_name='__main__')"
    return ['/usr/bin/python3','-I','-B','-c',shim,action,*extra]


def m01_clean():
    return subprocess.run(m01_command('inspect-clean'),check=False).returncode


def allocate_id(drill):
    day=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')
    # 6 random digits, checked against all existing event identifiers while
    # the global controller lock is held.
    existing=set()
    if os.path.lexists(EVENT_FILE):
        fd=os.open(EVENT_FILE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:
                raise Refused('unsafe events file')
            with os.fdopen(fd,encoding='utf-8') as f:
                fd=-1
                for line in f:
                    if len(line)>65536: raise Refused('invalid events file')
                    try: existing.add(json.loads(line).get('attempt_id'))
                    except (ValueError,AttributeError,TypeError): raise Refused('invalid events file')
        finally:
            if fd>=0: os.close(fd)
    for _ in range(100):
        candidate='%s-%s-%06d' % (drill,day,secrets.randbelow(1000000))
        if candidate not in existing: return candidate
    raise Refused('unable to allocate attempt id')


def action(args):
    require_root(); safe_dir()
    lock=open_lock('controller.lock')
    try:
        drill=args.drill
        if drill not in REGISTRY: raise Refused('drill not registered')
        state=read_state(drill)
        expected=getattr(args,'expect_run_id',None)
        if drill!='N04' and getattr(args,'n04_version',None) is not None: raise Refused('N04 version only applies to N04')
        if expected is not None:
            if not isinstance(expected,str) or not re.fullmatch(r'[0-9a-f]{24}',expected): raise Refused('invalid expected run ID')
            # A repeated reset may be a no-op when both CLI and drill are
            # clean, but it must never reset a different current attempt.
            if (not state and args.command!='reset') or (state and state.get('run_id')!=expected):
                raise Refused('expected run ID does not match current attempt')
        if drill in ('L04','N01','N04') and args.command in ('check','resolve','reset') and expected is None:
            raise Refused(drill+' requires --expect-run-id')
        if args.command=='start':
            if drill not in ('L03','L04','L01','N03','N02','N01','N04','L02','M01'): raise Refused('CLI start is not yet ownership-safe for this drill; use its documented entrypoint')
            variant=getattr(args,'variant',None)
            if drill in ('L03','L04','N02','N01','N04','L02','M01') and variant is not None: raise Refused('variant is only supported for L01')
            if drill=='L01':
                variant=variant or 'inode'
                if variant not in ('inode','deleted-open'): raise Refused('invalid L01 variant')
            if drill=='N03':
                variant=variant or '502'
                if variant not in ('502','504'): raise Refused('invalid N03 variant')
            if state: raise Refused('existing state requires reset or inspection')
            script_path(drill,'inject')
            attempt=allocate_id(drill)
            # Verify and append to the protected event stream before changing a drill.
            event(drill,attempt,'inject','STARTING',args.actor)
            state={'drill_id':drill,'attempt_id':attempt,'phase':'STARTING'}
            if drill=='N04':
                state['run_id']=os.urandom(12).hex(); state['n04_version']='recovery-v2'
            write_state(drill,state)
            try:
                extra=(variant,) if drill=='L01' else (('--504','--cli') if variant=='504' else ('--cli',)) if drill=='N03' else ()
                if drill=='N04':
                    extra=(state['run_id'],)
                    cp=invoke(drill,'inject',extra,capture=True,n04_version='recovery-v2')
                else:
                    cp=invoke(drill,'inject',extra,capture=True)
                rc=cp.returncode
                if cp.stdout: print(cp.stdout,end='')
                if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
                if rc==0:
                    receipt=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
                    if not isinstance(receipt,dict): raise Refused('invalid ownership receipt')
                    rid=receipt.get('run_id')
                    if not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid): raise Refused('invalid ownership receipt')
                    if drill=='L04':
                        if (set(receipt)!={'receipt','run_id','unit'} or receipt.get('receipt')!='L04_RUN_OWNER_V1'
                                or receipt.get('unit')!='opsdrill-l04-'+rid+'-fault.service'):
                            raise Refused('invalid ownership receipt')
                        controller='controller.py'; owner_args=(rid,)
                    elif drill=='L03':
                        if (set(receipt)!={'receipt','run_id','unit'} or receipt.get('receipt')!='L03_RUN_OWNER_V1'
                                or receipt.get('unit')!='opsdrill-l03-'+rid+'.service'):
                            raise Refused('invalid ownership receipt')
                        controller='l03_control.py'; owner_args=(rid,receipt['unit'])
                    elif drill=='M01':
                        if (set(receipt)!={'receipt','run_id','timer'} or receipt.get('receipt')!='M01_INDEX_OWNER_V1'
                                or receipt.get('timer')!='opsdrill-m01-recover-'+rid+'.timer'):
                            raise Refused('invalid ownership receipt')
                        controller='m01_owned.py'; owner_args=(rid,)
                    elif drill=='L02':
                        if (set(receipt)!={'receipt','run_id','timer'} or receipt.get('receipt')!='L02_CONFIG_OWNER_V1'
                                or receipt.get('timer')!='opsdrill-l02-recover-'+rid+'.timer'):
                            raise Refused('invalid ownership receipt')
                        controller='l02_cli.py'; owner_args=(rid,)
                    elif drill=='N04':
                        initial=receipt.get('initial')
                        if (set(receipt)!={'receipt','run_id','initial'} or receipt.get('receipt')!='N04_OWNER_V2' or rid!=state['run_id']
                                or not isinstance(initial,dict) or initial.get('event')!='injected'
                                or type(initial.get('fault_proven')) is not bool):
                            raise Refused('invalid ownership receipt')
                        # Persist the bound identity before any further check can fail.
                        state['run_id']=rid; state['phase']='NEEDS_RESET'; write_state(drill,state)
                        churn=initial.get('churn')
                        if initial['fault_proven'] and (initial.get('range')!=[40000,40031]
                                or type(initial.get('time_wait')) is not int or initial['time_wait']<1
                                or not isinstance(churn,dict) or type(churn.get('completed')) is not int
                                or churn['completed']<1 or type(churn.get('address_unavailable')) is not int
                                or churn['address_unavailable']<1 or churn.get('other_errors')!=[]):
                            raise Refused('inconsistent N04 injection evidence')
                        controller='n04_lifecycle.py'; owner_args=(rid,)
                    elif drill=='N01':
                        if set(receipt)!={'receipt','run_id'} or receipt.get('receipt')!='N01_OWNER_V1':
                            raise Refused('invalid ownership receipt')
                        controller='n01.py'; owner_args=(rid,)
                    elif drill=='N02':
                        if set(receipt)!={'receipt','run_id'} or receipt.get('receipt')!='N02_OWNER_V1':
                            raise Refused('invalid ownership receipt')
                        controller='n02.py'; owner_args=(rid,)
                    elif drill=='N03':
                        if (set(receipt)!={'receipt','run_id','timer'} or receipt.get('receipt')!='N03_'+variant+'_OWNER_V1'
                                or receipt.get('timer')!='opsdrill-n03-recover-'+rid+'.timer'):
                            raise Refused('invalid ownership receipt')
                        controller='n03_502.py'; owner_args=(rid,receipt['timer'])
                    elif variant=='inode':
                        if set(receipt)!={'receipt','run_id'} or receipt.get('receipt')!='L01_INODE_OWNER_V1':
                            raise Refused('invalid ownership receipt')
                        controller='l01_control.py'; owner_args=(rid,)
                    else:
                        if (set(receipt)!={'receipt','run_id','unit'} or receipt.get('receipt')!='L01_DELETED_OWNER_V1'
                                or receipt.get('unit')!='opsdrill-l01-deleted-'+rid+'.service'):
                            raise Refused('invalid ownership receipt')
                        controller='l01_deleted.py'; owner_args=(rid,receipt['unit'])
                    if drill=='N04':
                        owner_command=n04_command('check',owner_args,'recovery-v2')
                    elif drill=='L04':
                        owner_command=l04_command('verify-owner',owner_args)
                    elif drill=='M01':
                        owner_command=m01_command('verify-owner',owner_args)
                    elif drill=='L02':
                        owner_command=l02_command('verify-owner',owner_args)
                    else:
                        owner_path=n01_controller() if drill=='N01' else n02_controller() if drill=='N02' else secure_file(REGISTRY[drill]+'/'+controller)
                        owner_command=['/usr/bin/python3',str(owner_path),'verify-owner',*owner_args]
                    check=subprocess.run(owner_command,capture_output=True,text=True,check=False)
                    if drill=='N04':
                        n04_check_outcome(check,rid)
                    elif check.returncode: raise Refused('ownership verification failed')
                    state['run_id']=rid
                    if drill in ('L01','N03'): state['variant']=variant
                    if 'unit' in receipt: state['unit']=receipt['unit']
                    if 'timer' in receipt: state['timer']=receipt['timer']
            except Exception:
                state['phase']='NEEDS_RESET'; write_state(drill,state); raise
            state['phase']='ACTIVE' if rc==0 else 'NEEDS_RESET'
            write_state(drill,state)
            proven=(drill!='N04' or (rc==0 and receipt['initial']['fault_proven']))
            event(drill,attempt,'inject','PASS' if rc==0 and proven else 'FAIL',args.actor)
            return 2 if rc==0 and not proven else rc
        if args.command=='check':
            # A clean environment is not a passed exercise: only a recorded,
            # verified active attempt can be checked as a recovery.
            if not state or state['phase']!='ACTIVE':
                raise Refused('no active CLI-owned attempt')
            if drill=='N04':
                cp=invoke(drill,'check',(state['run_id'],),capture=True,n04_version=state.get('n04_version','legacy'))
                if cp.stdout: print(cp.stdout,end='')
                if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
                try: rc=n04_check_outcome(cp,state['run_id'])
                except Refused: rc=2
                pending=rc==1
            elif drill=='L04':
                cp=invoke(drill,'check',(state['run_id'],),capture=True)
                rc=cp.returncode
                if cp.stdout: print(cp.stdout,end='')
                if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
                try: observed=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
                except (TypeError,ValueError,Refused): observed={}
                pending=(rc==1 and isinstance(observed,dict) and observed.get('status')=='FAULT')
            elif drill in ('N01','N02','L02','M01'):
                cp=invoke(drill,'check',(state['run_id'],),capture=True)
                rc=cp.returncode
                if cp.stdout: print(cp.stdout,end='')
                if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
                pending=(rc==1 and (cp.stdout.strip().startswith('FAIL: M01 injected, target index invisible; plan uses ') if drill=='M01' else cp.stdout.strip()==('L02 fault confirmed' if drill=='L02' else 'N01 DNS fault observed' if drill=='N01' else 'N02 fault confirmed: 8080 timed out')))
            elif drill in ('L01','N03'):
                extra=l01_args(state) if drill=='L01' else (state['run_id'],)
                rc=invoke(drill,'check',extra); pending=False
            elif drill=='L03':
                cp=invoke(drill,'check',capture=True)
                rc=cp.returncode
                if cp.stdout: print(cp.stdout,end='')
                if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
                try: observed=json.loads(cp.stdout)
                except (TypeError,ValueError): observed={}
                pending=isinstance(observed,dict) and observed.get('status')=='RUNNING'
            else:
                rc=invoke(drill,'check'); pending=False
            result='PASS' if rc==0 else 'PENDING' if pending else 'FAIL'
            if state: event(drill,state['attempt_id'],'check',result,args.actor)
            return rc
        if args.command=='resolve':
            if drill not in ('L04','N01','N04') or not state or state['phase']!='ACTIVE':
                raise Refused('no active CLI-owned attempt')
            try:
                if drill=='N04':
                    cp=invoke(drill,'resolve',(state['run_id'],),capture=True,n04_version=state.get('n04_version','legacy'))
                    if cp.stdout: print(cp.stdout,end='')
                    if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
                    try: rc=0 if n04_resolve_ok(cp,state['run_id']) else 2
                    except Refused: rc=2
                else:
                    rc=invoke(drill,'resolve',(state['run_id'],))
            except Exception:
                state['phase']='NEEDS_RESET'; write_state(drill,state); raise
            if rc!=0:
                state['phase']='NEEDS_RESET'; write_state(drill,state)
            return rc
        if args.command=='reset' and drill=='N04':
            version=state.get('n04_version','legacy') if state else getattr(args,'n04_version',None) or 'legacy'
            requested=getattr(args,'n04_version',None)
            if requested and requested!=version: raise Refused('N04 version does not match state')
            if state and (state['phase'] not in (('STARTING','ACTIVE','NEEDS_RESET') if version=='recovery-v2' else ('ACTIVE','NEEDS_RESET')) or state.get('run_id')!=expected):
                raise Refused('ambiguous N04 ownership; inspect directly')
            try:
                cp=invoke(drill,'reset',(expected,),capture=True,n04_version=version)
                if cp.stdout: print(cp.stdout,end='')
                if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
                try: rc=0 if n04_reset_ok(cp,expected) else 2
                except Refused: rc=2
                if state:
                    if rc==0:
                        event(drill,state['attempt_id'],'reset','PASS',args.actor)
                        os.unlink(state_path(drill))
                    else:
                        state['phase']='NEEDS_RESET'; write_state(drill,state)
                        event(drill,state['attempt_id'],'reset','FAIL',args.actor)
                return rc
            except Exception:
                if state:
                    state['phase']='NEEDS_RESET'; write_state(drill,state)
                raise
        if args.command=='reset' and drill=='N01':
            if state and (state['phase'] not in ('ACTIVE','NEEDS_RESET') or state.get('run_id')!=expected):
                raise Refused('ambiguous N01 ownership; inspect directly')
            try:
                # The controller validates the per-run completion receipt when no run is active.
                rc=invoke(drill,'reset',(expected,))
                if state:
                    if rc==0:
                        event(drill,state['attempt_id'],'reset','PASS',args.actor)
                        os.unlink(state_path(drill))
                    else:
                        state['phase']='NEEDS_RESET'; write_state(drill,state)
                        event(drill,state['attempt_id'],'reset','FAIL',args.actor)
                return rc
            except Exception:
                if state:
                    state['phase']='NEEDS_RESET'; write_state(drill,state)
                raise
        if args.command=='reset' and drill=='L04':
            if not state:
                if not l04_receipt(expected): raise Refused('unknown L04 CLI run')
                return invoke(drill,'reset',(expected,))
            if state['phase'] not in ('ACTIVE','NEEDS_RESET') or state.get('run_id')!=expected:
                raise Refused('ambiguous L04 ownership; inspect directly')
            try:
                rc=invoke(drill,'reset',(expected,))
                if rc==0:
                    l04_mark_done(expected)
                    event(drill,state['attempt_id'],'reset','PASS',args.actor)
                    os.unlink(state_path(drill))
                else:
                    state['phase']='NEEDS_RESET'; write_state(drill,state)
                    event(drill,state['attempt_id'],'reset','FAIL',args.actor)
                return rc
            except Exception:
                state['phase']='NEEDS_RESET'; write_state(drill,state); raise
        if args.command=='reset':
            if drill in ('L01','N03','N02','L02','M01'):
                if not state or state['phase']!='ACTIVE':
                    clean=l01_clean() if drill=='L01' else n03_clean() if drill=='N03' else n02_clean() if drill=='N02' else l02_clean() if drill=='L02' else m01_clean()
                    if clean!=0: raise Refused('ambiguous ownership; inspect the drill directly')
                    if state:
                        event(drill,state['attempt_id'],'reset','CLEAN',args.actor)
                        os.unlink(state_path(drill))
                    return 0
                extra=l01_args(state) if drill=='L01' else (state['run_id'],)
                rc=invoke(drill,'reset',extra)
                if rc==0:
                    event(drill,state['attempt_id'],'reset','PASS',args.actor)
                    os.unlink(state_path(drill))
                else:
                    state['phase']='NEEDS_RESET'; write_state(drill,state)
                    event(drill,state['attempt_id'],'reset','FAIL',args.actor)
                return rc
            if drill=='L03' and (not state or state['phase']!='ACTIVE'):
                # Do not stop or delete anything without a receipt. The L03
                # check independently rejects orphan runs/units and bad health.
                rc=invoke(drill,'check')
                if rc!=0: raise Refused('ambiguous ownership; inspect the drill directly')
                if state:
                    event(drill,state['attempt_id'],'reset','CLEAN',args.actor)
                    os.unlink(state_path(drill))
                return 0
            if not state: raise Refused('no CLI-owned attempt; inspect the drill directly')
            if state['phase']!='ACTIVE' or drill!='L03':
                raise Refused('ambiguous ownership; inspect the drill directly before cleanup')
            rc=invoke(drill,'reset',(state['run_id'],state['unit']))
            if rc==0:
                event(drill,state['attempt_id'],'reset','PASS',args.actor)
                os.unlink(state_path(drill))
            else:
                state['phase']='NEEDS_RESET'; write_state(drill,state)
                event(drill,state['attempt_id'],'reset','FAIL',args.actor)
            return rc
        if not state or state['phase']!='ACTIVE': raise Refused('no active CLI-owned attempt')
        if args.command=='hint':
            hint=secure_file(REGISTRY[drill]+'/hints.md')
            if hint.stat().st_size>16384: raise Refused('hints file too large')
            print(hint.read_text(encoding='utf-8'))
            event(drill,state['attempt_id'],'hint','PASS',args.actor)
            return 0
        if args.command=='note':
            # Do not store free-form text, which can contain credentials or private data.
            event(drill,state['attempt_id'],'diagnosis','PASS',args.actor)
            print('Diagnosis marker recorded; free-form text is not stored.')
            return 0
        raise Refused('unsupported action')
    finally: os.close(lock)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('list'); sub.add_parser('status'); sub.add_parser('report')
    for name in ('start','check','resolve','reset','hint','note'):
        s=sub.add_parser(name); s.add_argument('drill'); s.add_argument('--actor',choices=('user','agent','unknown'),default='unknown')
        if name=='start': s.add_argument('--variant',choices=('inode','deleted-open','502','504'))
        if name in ('check','resolve','reset'): s.add_argument('--expect-run-id')
        if name=='reset': s.add_argument('--n04-version',choices=('legacy','recovery-v2'))
        if name=='note': s.add_argument('--kind',choices=('diagnosis',),required=True)
    args=p.parse_args(argv)
    if args.command=='list':
        for drill,path in sorted(REGISTRY.items()): print(drill,path)
        return 0
    if args.command=='status':
        if os.geteuid()!=0: raise Refused('root required to read protected state')
        if not os.path.lexists(STATE_ROOT):
            for drill in sorted(REGISTRY): print(drill,'NO_CLI_STATE')
            return 0
        safe_dir()
        for drill in sorted(REGISTRY):
            state=read_state(drill)
            print(drill, state['phase'] if state else 'NO_CLI_STATE')
        return 0
    if args.command=='report':
        return subprocess.run([sys.executable,str(PROJECT/'scripts/report.py'),'--markdown'],check=False).returncode
    return action(args)


if __name__=='__main__':
    try: sys.exit(main())
    except (Refused,OSError,ValueError,json.JSONDecodeError) as exc:
        print('opsdrill: '+str(exc),file=sys.stderr); sys.exit(2)
