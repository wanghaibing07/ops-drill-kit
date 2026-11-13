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
REGISTRY = {'M01':'drills/mysql/M01', 'M02':'drills/mysql/M02', 'M03':'drills/mysql/M03', 'M04':'drills/mysql/M04', 'L01':'drills/linux/L01', 'L02':'drills/linux/L02', 'L03':'drills/linux/L03', 'L04':'drills/linux/L04', 'N03':'drills/network/N03', 'N02':'drills/network/N02', 'N01':'drills/network/N01', 'N04':'drills/network/N04'}
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
        obj=json.loads(raw,object_pairs_hook=unique_pairs) if drill in ('N04','M03','M04','C01','L02') else json.loads(raw)
    finally: os.close(fd)
    if not isinstance(obj,dict) or obj.get('drill_id')!=drill or obj.get('phase') not in ('STARTING','ACTIVE','NEEDS_RESET'):
        raise Refused('invalid state')
    attempt=obj.get('attempt_id')
    if not isinstance(attempt,str) or not re.fullmatch(re.escape(drill)+r'-[0-9]{8}-[0-9]{6}',attempt):
        raise Refused('invalid attempt id')
    if drill=='C01':
        if (set(obj)-{'drill_id','attempt_id','phase','run_id','last_check'} or
                not isinstance(obj.get('run_id'),str) or not re.fullmatch(r'[0-9a-f]{24}',obj['run_id']) or
                obj.get('last_check') not in (None,'FAULT_PRESENT','RECOVERED_PARTIAL')):
            raise Refused('invalid owned C01 identity')
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
    if drill=='M02':
        rid=obj.get('run_id')
        if (not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid)
                or obj.get('m02_version','legacy') not in ('legacy','baseline-v2')):
            raise Refused('invalid owned M02 identity')
    if obj.get('phase')=='ACTIVE' and drill=='M01':
        rid=obj.get('run_id')
        if (not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid)
                or obj.get('timer')!='opsdrill-m01-recover-'+rid+'.timer'):
            raise Refused('invalid owned M01 identity')
    if drill=='L02' and obj.get('l02_version','legacy') not in ('legacy','recovery-v2'):
        raise Refused('invalid L02 version')
    if obj.get('phase')=='ACTIVE' and drill=='L02':
        rid=obj.get('run_id')
        if (not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid)
                or obj.get('timer')!='opsdrill-l02-recover-'+rid+'.timer'):
            raise Refused('invalid owned L02 identity')
    if drill=='M03' and (obj.get('m03_version')!='mysql-v1' or not isinstance(obj.get('run_id'),str)
            or not re.fullmatch(r'[0-9a-f]{24}',obj['run_id'])):
        raise Refused('invalid owned M03 identity')
    if drill=='M04' and (obj.get('m04_version') not in ('synthetic-v1','synthetic-v2','synthetic-v3','synthetic-v4') or not isinstance(obj.get('run_id'),str)
            or not re.fullmatch(r'[0-9a-f]{16}',obj['run_id'])):
        raise Refused('invalid owned M04 identity')
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


def validate_bounded_io(before, after, *, run_id, elapsed_ns, application_read_bytes,
             storage_read_bytes, health_before, health_after):
    """Return PASS only for complete same-device, same-cgroup bounded evidence.

    Hardware condition and attribution of host-wide iowait are outside scope.
    """
    import re
    if not isinstance(run_id,str) or not re.fullmatch(r'[0-9a-f]{24}',run_id):return False
    if not isinstance(before,dict) or not isinstance(after,dict):return False
    keys={'device','limit_device','unit','limit_bps','disk_read_sectors','cgroup_read_bytes','monotonic_ns'}
    if set(before)!=keys or set(after)!=keys:return False
    if before['device']!=after['device'] or before['limit_device']!=after['limit_device']:return False
    if before['unit']!=after['unit'] or before['unit']!='opsdrill-l03-'+run_id+'.service':return False
    if before['limit_bps']!=32000000 or after['limit_bps']!=32000000:return False
    for sample in (before,after):
        if not isinstance(sample['device'],str) or not re.fullmatch(r'[0-9]+:[0-9]+',sample['device']):return False
        if not isinstance(sample['limit_device'],str) or not re.fullmatch(r'[0-9]+:[0-9]+',sample['limit_device']):return False
        if any(type(sample[k]) is not int or sample[k]<0 for k in ('disk_read_sectors','cgroup_read_bytes','monotonic_ns','limit_bps')):return False
    if type(elapsed_ns) is not int or not 0<elapsed_ns<=30000000000:return False
    if type(application_read_bytes) is not int or application_read_bytes!=268435456:return False
    if type(storage_read_bytes) is not int or storage_read_bytes<67108864:return False
    if health_before is not True or health_after is not True:return False
    if not 0<after['monotonic_ns']-before['monotonic_ns']<=30000000000:return False
    if after['disk_read_sectors']<=before['disk_read_sectors']:return False
    if after['cgroup_read_bytes']<=before['cgroup_read_bytes']:return False
    return True


def l03_details_valid(details):
    if not isinstance(details,dict) or set(details)!={'run_id','l03_contract','io_evidence','elapsed_ns','read_bytes','storage_read_bytes','health_before','health_after'}: return False
    if details['l03_contract']!='bounded-io-v1': return False
    evidence=details['io_evidence']
    if not isinstance(evidence,dict) or set(evidence)!={'before','after'}: return False
    return validate_bounded_io(evidence['before'],evidence['after'],run_id=details['run_id'],
        elapsed_ns=details['elapsed_ns'],application_read_bytes=details['read_bytes'],
        storage_read_bytes=details['storage_read_bytes'],health_before=details['health_before'],health_after=details['health_after'])


def event(drill,attempt,kind,result,actor,details=None):
    obj={'drill_id':drill,'attempt_id':attempt,'event':kind,'result':result,
         'actor':actor,'ts':datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'boot_id':BOOT_ID.read_text(encoding='ascii').strip(),'monotonic_ns':time.monotonic_ns()}
    if details is not None:
        if drill=='M04':
            if set(details)-{'run_id','m04_version','expected_auditor_sha256','verified_auditor_sha256'}: raise Refused('invalid event details')
        elif drill=='L03':
            if kind!='check' or result!='PASS' or not l03_details_valid(details): raise Refused('invalid L03 evidence')
        else: raise Refused('invalid event details')
        obj.update(details)
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


def protected_n03_call(filename, digest, action, extra=(), capture=False, directory='n03'):
    dfd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if directory not in ('n03','c01-v2'): raise Refused('unsupported controller directory')
        for part in ('usr','local','libexec','opsdrill',directory):
            st=os.fstat(dfd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
                raise Refused('unsafe N03 installation path')
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
            os.close(dfd); dfd=new
        st=os.fstat(dfd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
            raise Refused('unsafe N03 installation directory')
        fd=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dfd)
    finally: os.close(dfd)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022 or st.st_size>131072:
            raise Refused('unsafe installed controller')
        data=b''
        while len(data)<=131072:
            chunk=os.read(fd,min(16384,131073-len(data)))
            if not chunk: break
            data+=chunk
        if len(data)!=st.st_size or hashlib.sha256(data).hexdigest()!=digest:
            raise Refused('installed controller version mismatch')
        os.lseek(fd,0,os.SEEK_SET)
        return subprocess.run(['/usr/bin/python3','-I','-B','/proc/self/fd/'+str(fd),action,*extra],
                              pass_fds=(fd,),capture_output=capture,text=capture,timeout=120,check=False,
                              env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'})
    finally: os.close(fd)


def n03_call(action,extra=(),capture=False):
    return protected_n03_call('n03_502.py','8b527cad68557f7294be8580f58923c5e7a1563daf521b44087d19724bed6d5c',action,extra,capture)


def c01_call(action,actor,expected=None,capture=False):
    args=(actor,) if expected is None else (actor,expected)
    return protected_n03_call('c01_control.py','29b84c493a889ff2ea6b624f23e3e98f6a15096eed5a648e676bed08d928b60a',action,args,capture,directory='c01-v2')


def script_path(drill,action):
    if drill not in REGISTRY or action not in ('inject','check','reset'):
        raise Refused('drill or action not registered')
    if drill=='L04': return Path('/usr/local/libexec/opsdrill/l04/controller.py')
    if drill=='N04': return Path('/usr/local/libexec/opsdrill/n04/n04_lifecycle.py')
    if drill=='N01': return n01_controller()
    if drill=='N03': return Path('/usr/local/libexec/opsdrill/n03/n03_502.py')
    return secure_file(REGISTRY[drill]+'/'+action+'.sh')


def invoke(drill,action,extra=(),capture=False,n04_version='legacy',l02_version='legacy'):
    if drill=='N03':
        cp=n03_call(action,extra,capture)
        return cp if capture else cp.returncode
    command=(l04_command('start' if action=='inject' else action,extra) if drill=='L04'
             else n04_command('start' if action=='inject' else action,extra,n04_version) if drill=='N04'
             else m01_command('start' if action=='inject' else action,extra) if drill=='M01'
             else l02_command('start' if action=='inject' else action,extra,l02_version) if drill=='L02'
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
    return n03_call('inspect-clean').returncode


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
    if digest!='954c3bc7f4e4c59156d7ae612ae107de76ee21204cf8333ce989a721cd5cc8a8':
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


L02_V2_MANIFEST = {'l02_audit.py': 'fbed2c8254298d2a1a949ba67445729934edf3ab81851d9b6f7c88878094683f', 'l02_cli.py': '553d98696b7b57f15619681d381c2b7e445fed2dfce6857d62c7fcc2a26a87ab', 'l02_config_lifecycle.py': 'a0cd65197f4411340eba0a133096e477212f880e08729e9ad372c1faa905c4bc', 'l02_initialize.py': 'f4b9dce0af162aa4dd7b46e7baffed02690cda71d918435b7e9bd15df8999a59', 'l02_isolated.py': '73b1d0119f2e25b807ae6555ff6aaa5196865aa89280fbbf68917944b1aecedc', 'l02_journal_avc.py': '9b1433956277e122134d536adab232b92f7589f6b4d27715c850518c923f1d8e', 'l02_linux_config.py': 'e20aa533d9151ca868c2c14ecc46f3914888f2a1cee7c5969bde95d9c6e66078', 'l02_linux_config_backend.py': 'b521fe01a23a6539a27810a92d48702079ae96321a41dd40f1518c4ff7a168ce', 'l02_linux_evidence.py': 'f1be95bdc198e346209aa8ac3e7b37260654b08080336fb61edf5b6d6ee12bcd', 'l02_linux_inspect.py': '6614d7e15b1d93ee9a14a2ddcdfa4809bc7bc5c92db3e2d559019fdb32e4c8f4', 'l02_linux_journal.py': '82ddac3719b4a550007bc4806bae15a9c66ee7af3e12a12524939a8dfc0c239b', 'l02_policy.py': '1f0256043cd16b373673c088740581fec810fa1db0d600fdcd91a256fa0b5445', 'l02_prepare.py': '55188b443644f17e5632074df20e1e1a7f8deea4215b21e962df73a9e5015bff', 'l02_watchdog_arm.py': 'ab58c9c75415c4cc643fde355e8996c68948fa0aedf479a4f6df6711e7fdacc8', 'l02_watchdog_helper.py': 'e03d4bdbf157f629603202d6a3e2b83fbebf0f8b425ad2e1f1108a73d0f5d52d'}


def l02_command(action,extra=(),version='legacy'):
    if version not in ('legacy','recovery-v2'): raise Refused('unknown L02 version')
    root=Path('/usr/local/libexec/opsdrill/l02' if version=='legacy' else '/usr/local/libexec/opsdrill/l02-recovery-v2')
    manifest=L02_MANIFEST if version=='legacy' else L02_V2_MANIFEST
    for part in (root,*root.parents):
        try: st=part.lstat()
        except OSError as exc: raise Refused('L02 installation missing or inaccessible') from exc
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise Refused('L02 installation path is not root-controlled')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if set(os.listdir(fd))!=set(manifest): raise Refused('unexpected L02 installation files')
        for name,expected in manifest.items():
            item=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            with os.fdopen(item,'rb') as stream:
                st=os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o022 or st.st_size>1048576:
                    raise Refused('unsafe L02 module')
                if hashlib.sha256(stream.read(1048577)).hexdigest()!=expected:
                    raise Refused('L02 module version mismatch')
    finally: os.close(fd)
    shim="import runpy,sys;sys.path.insert(0,"+repr(str(root))+");runpy.run_path("+repr(str(root/"l02_cli.py"))+",run_name='__main__')"
    return ['/usr/bin/python3','-I','-B','-c',shim,action,*extra]


def l02_clean(version='legacy'):
    return subprocess.run(l02_command('inspect-clean',version=version),check=False).returncode


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


M03_MANIFEST = {'mysql_lifecycle.py': 'e1bc6b0895114652781b96c753760fff7ba83f82fad2c4e89f03d5a3de81b457', 'm04_controller.py': '46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9', 'm03_vm_probe.py': '0af53e4b3f18819699d4c68dc44f7a3cdc1ae4abe2696f2b661f92a4bfd53aac'}
M03_DIAG_STAGES = frozenset(('WORKER_IDENTITY', 'DEPENDENCIES', 'CONTROLLER_SETUP', 'DB_DIRECTORY',
    'CONTROLLER_LOCK', 'STATE_INIT', 'DB_START', 'PREPARE_LIMIT', 'PREPARE_LOGGING', 'PREPARE_AUDIT',
    'PREPARE_ACCOUNT_CHECK', 'PREPARE_MEMFD', 'PREPARE_INTENT', 'PREPARE_CREATE', 'PREPARE_GRANTS',
    'PREPARE_CONNECT', 'PREPARE_READY', 'CONTROL_SOCKET', 'SERVE', 'INJECT', 'CHECK', 'RESOLVE',
    'RESET', 'CLEANUP_HOLDERS', 'CLEANUP_IDENTITY', 'CLEANUP_ACCOUNT', 'CLEANUP_INSTANCES', 'CLEANUP_RECEIPT'))
M03_DIAG_ERRORS = frozenset(('Refused', 'SafetyError', 'TimeoutError', 'TimeoutExpired', 'FileNotFoundError',
    'FileExistsError', 'PermissionError', 'OSError', 'ValueError', 'KeyError', 'TypeError',
    'RuntimeError', 'ImportError', 'AttributeError', 'JSONDecodeError', 'OtherError', 'UNKNOWN'))


def m03_command(action,rid):
    if action not in ('start','inject','check','resolve','reset') or not re.fullmatch(r'[0-9a-f]{24}',rid):
        raise Refused('invalid M03 controller request')
    root=Path('/usr/local/libexec/opsdrill/m03-mysql-v1')
    for part in (root,*root.parents):
        try: st=part.lstat()
        except OSError as exc: raise Refused('M03 installation missing or inaccessible') from exc
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise Refused('M03 installation path is not root-controlled')
    manifest=(json.dumps(M03_MANIFEST,sort_keys=True)+'\n').encode('ascii')
    expected=dict(M03_MANIFEST,**{'manifest.json':hashlib.sha256(manifest).hexdigest()})
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if set(os.listdir(fd))!=set(expected): raise Refused('unexpected M03 installation files')
        for name,digest in expected.items():
            item=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            with os.fdopen(item,'rb') as stream:
                st=os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o022 or st.st_size>1048576:
                    raise Refused('unsafe M03 module')
                if hashlib.sha256(stream.read(1048577)).hexdigest()!=digest:
                    raise Refused('M03 module version mismatch')
    finally: os.close(fd)
    return ['/usr/bin/python3','-I','-B',str(root/'mysql_lifecycle.py'),action,rid]


def m03_invoke(action,rid):
    # Never relay raw child output: it may contain diagnostic data.
    try:
        cp=subprocess.run(m03_command(action,rid),capture_output=True,text=True,check=False,
                          timeout=750 if action=='start' else 420,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
        if cp.returncode==2:
            try:
                obj=json.loads(cp.stderr,object_pairs_hook=unique_pairs)
                diagnostic=obj.get('diagnostic') if isinstance(obj,dict) and obj.get('status')=='UNCONFIRMED' else None
                if (isinstance(diagnostic,dict) and set(diagnostic)=={'stage','error'}
                        and diagnostic['stage'] in M03_DIAG_STAGES and diagnostic['error'] in M03_DIAG_ERRORS):
                    print(json.dumps(diagnostic,sort_keys=True),file=sys.stderr)
            except (TypeError,ValueError,Refused):
                pass
        return cp
    except subprocess.TimeoutExpired as exc:
        raise Refused('M03 controller timed out; retain run ID') from exc


def m03_response(cp,rid,action):
    try: obj=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
    except (TypeError,ValueError,Refused): raise Refused('invalid M03 response')
    if not isinstance(obj,dict) or obj.get('run_id')!=rid: raise Refused('invalid M03 response identity')
    status=obj.get('status')
    if action=='start': valid=(cp.returncode==0 and obj=={'run_id':rid,'status':'READY','db_scope':'isolated_socket_only'})
    elif action=='inject': valid=(cp.returncode==0 and obj=={'run_id':rid,'status':'INJECTED'})
    elif action=='resolve': valid=(cp.returncode==0 and obj=={'run_id':rid,'status':'RELEASED'})
    elif action=='reset': valid=(cp.returncode==0 and obj=={'run_id':rid,'status':'STOPPED'})
    elif action=='check' and status=='FAULT':
        valid=(cp.returncode==1 and set(obj)=={'run_id','status','sleep_connections','mysql_error'}
               and type(obj['sleep_connections']) is int and 1<=obj['sleep_connections']<=12
               and type(obj['mysql_error']) is int and obj['mysql_error']==1040)
    elif action=='check' and status=='RECOVERED':
        valid=(cp.returncode==0 and set(obj)=={'run_id','status','sleep_connections','connection'}
               and type(obj['sleep_connections']) is int and obj['sleep_connections']==0 and obj['connection']=='OK')
    else: valid=False
    if not valid: raise Refused('M03 evidence not confirmed')
    return obj


def m03_action(args,state,expected):
    drill='M03'
    if args.command=='start':
        if getattr(args,'variant',None) is not None: raise Refused('M03 does not accept a variant')
        if state: raise Refused('existing state requires reset or inspection')
        attempt=allocate_id(drill)
        event(drill,attempt,'inject','STARTING',args.actor)
        rid=secrets.token_hex(12)
        state={'drill_id':drill,'attempt_id':attempt,'phase':'STARTING','run_id':rid,'m03_version':'mysql-v1'}
        write_state(drill,state)
        print(json.dumps({'run_id':rid,'status':'STARTING'}),flush=True)
        try:
            m03_response(m03_invoke('start',rid),rid,'start')
            m03_response(m03_invoke('inject',rid),rid,'inject')
            observed=m03_response(m03_invoke('check',rid),rid,'check')
            if observed['status']!='FAULT': raise Refused('M03 fault not established')
            state['phase']='ACTIVE'; write_state(drill,state)
            event(drill,attempt,'inject','PASS',args.actor)
            print(json.dumps(observed,sort_keys=True))
            return 0
        except Exception:
            state['phase']='NEEDS_RESET'; write_state(drill,state)
            event(drill,attempt,'inject','FAIL',args.actor)
            raise
    if args.command=='reset':
        if state and (state['phase'] not in ('STARTING','ACTIVE','NEEDS_RESET') or state.get('run_id')!=expected):
            raise Refused('ambiguous M03 ownership')
        try:
            result=m03_response(m03_invoke('reset',expected),expected,'reset')
            if state:
                event(drill,state['attempt_id'],'reset','PASS',args.actor)
                os.unlink(state_path(drill))
            print(json.dumps(result,sort_keys=True))
            return 0
        except Exception:
            if state:
                state['phase']='NEEDS_RESET'; write_state(drill,state)
                event(drill,state['attempt_id'],'reset','FAIL',args.actor)
            raise
    if args.command in ('check','resolve'):
        if not state or state['phase']!='ACTIVE': raise Refused('no active CLI-owned M03 attempt')
        rid=state['run_id']
        try:
            if args.command=='resolve':
                m03_response(m03_invoke('resolve',rid),rid,'resolve')
                result=m03_response(m03_invoke('check',rid),rid,'check')
                if result['status']!='RECOVERED': raise Refused('M03 recovery not confirmed')
                print(json.dumps(result,sort_keys=True))
                return 0
            result=m03_response(m03_invoke('check',rid),rid,'check')
            pending=result['status']=='FAULT'
            event(drill,state['attempt_id'],'check','PENDING' if pending else 'PASS',args.actor)
            print(json.dumps(result,sort_keys=True))
            return 1 if pending else 0
        except Exception:
            state['phase']='NEEDS_RESET'; write_state(drill,state)
            if args.command=='check': event(drill,state['attempt_id'],'check','FAIL',args.actor)
            raise
    # hint and note use the existing generic path, without weakening state checks.
    return m03_other(args,state)


def m03_other(args,state):
    if not state or state['phase']!='ACTIVE': raise Refused('no active CLI-owned attempt')
    if args.command=='hint':
        hint=secure_file(REGISTRY['M03']+'/hints.md')
        if hint.stat().st_size>16384: raise Refused('hints file too large')
        print(hint.read_text(encoding='utf-8'))
        event('M03',state['attempt_id'],'hint','PASS',args.actor)
        return 0
    if args.command=='note':
        event('M03',state['attempt_id'],'diagnosis','PASS',args.actor)
        print('Diagnosis marker recorded; free-form text is not stored.')
        return 0
    raise Refused('unsupported M03 action')


# M04 candidate integration. Review installation and manifest before deployment.
M04_MANIFEST = {'m04_controller.py': '46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9', 'm04_business.py': '17c401b9144efc3d2e0b7b5f72ca20da04220a512b4514a564405b8a35a872ef', 'm04_replay_account.py': '15a112d035563f1a2e8088c4a7c7f8ffc6ee5e7425d3f9ba68a8dfcb1d52234d', 'vm_replay_probe.py': '569af2c7ef921b09d005581d860f64681e78735f019e1d2698672fffbb10da97', 'pitr_audit.py': '3b6d5fa1ee4c5227d3ae33a825b92bac8c96d6b054a80bfda2537ea03cb6c51e', 'sealed_replay.py': '5e8487ab4b6ab7acc6b3dc961456159c9a1ce30a0cce5d784b9d43e503597e7f', 'stream_envelope.py': '95b9307b280e568df1332657e67b525198b4159f3e498c3a5ae3a14128a9c520', 'continuation/mysql_lifecycle_candidate.py': '97de74a7581515184b83e716191d932fc43044e13b6419e0655f552027e23885', 'continuation/mysql_synthetic_drill.py': '8b03d6c482a420ac9747e4ca5b9898590e22da342a2599eeb1014fd84ebd9249', 'continuation/mysql_live_identity.py': 'c294cfa07973ef9342d4ca65147da14acbe6fa155ad29623edcda31fc48a42be', 'continuation/mysql_reset_gate.py': 'eff466c8ad9dc5f7d2012a1b93aca33ffbb763d52ba8c39429f34ad7623178af', 'continuation/mysql_backup_gate.py': '3761d0323109a48795f8e222ae4fea4d104bdd56202a362ee0567946fff1b8bb', 'continuation/mysql_binlog_gate.py': 'f35dc69743710157359e1cbb55f4f4b6997b52c687c8f0185843a7a3d97ea917', 'continuation/mysql_fixture_gate.py': '5729222c7028879e36bee1cbfd50d7124cefb0d5459ef290906bce73bc286e15'}


M04_V2_MANIFEST = {'m04_controller.py': '46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9', 'm04_business.py': '17c401b9144efc3d2e0b7b5f72ca20da04220a512b4514a564405b8a35a872ef', 'm04_replay_account.py': '15a112d035563f1a2e8088c4a7c7f8ffc6ee5e7425d3f9ba68a8dfcb1d52234d', 'vm_replay_probe.py': '569af2c7ef921b09d005581d860f64681e78735f019e1d2698672fffbb10da97', 'pitr_audit.py': '3b6d5fa1ee4c5227d3ae33a825b92bac8c96d6b054a80bfda2537ea03cb6c51e', 'sealed_replay.py': '5e8487ab4b6ab7acc6b3dc961456159c9a1ce30a0cce5d784b9d43e503597e7f', 'stream_envelope.py': '95b9307b280e568df1332657e67b525198b4159f3e498c3a5ae3a14128a9c520', 'continuation/mysql_lifecycle_candidate.py': '9b025309dfcb3ab5bc1b3db975fceb2d8cab3672ed912f44c03176fa7879e746', 'continuation/mysql_synthetic_drill.py': '1b7f6df409438ba7653bfd0b1b94c7ab41b0e93531d1a4b0488cd4bd5d586cb0', 'continuation/mysql_live_identity.py': 'c294cfa07973ef9342d4ca65147da14acbe6fa155ad29623edcda31fc48a42be', 'continuation/mysql_reset_gate.py': 'eff466c8ad9dc5f7d2012a1b93aca33ffbb763d52ba8c39429f34ad7623178af', 'continuation/mysql_backup_gate.py': '3761d0323109a48795f8e222ae4fea4d104bdd56202a362ee0567946fff1b8bb', 'continuation/mysql_binlog_gate.py': 'f35dc69743710157359e1cbb55f4f4b6997b52c687c8f0185843a7a3d97ea917', 'continuation/mysql_fixture_gate.py': '5729222c7028879e36bee1cbfd50d7124cefb0d5459ef290906bce73bc286e15'}


M04_V4_MANIFEST = dict(M04_V2_MANIFEST, **{'continuation/mysql_lifecycle_candidate.py': 'e22888c2036e9204bf07313c89873de1bb707103d5ee2530465153bd44ca372f'})

def m04_digest_matches(name, expected, actual, version, action):
    # Retain the old pinned runtime for existing runs; accept the audited fix too.
    return actual == expected or (version in ('synthetic-v1','synthetic-v2') and action != 'start' and
        name == 'pitr_audit.py' and expected == '3b6d5fa1ee4c5227d3ae33a825b92bac8c96d6b054a80bfda2537ea03cb6c51e' and
        actual == '435103f2a50e37300f0746fea814bf479a35234f77d0c4e7944c157b0cf294cd')


def m04_command(action,rid,version='synthetic-v1'):
    if action not in ('start','check','resolve','reset') or not re.fullmatch(r'[0-9a-f]{16}',rid):
        raise Refused('invalid M04 controller request')
    if version not in ('synthetic-v1','synthetic-v2','synthetic-v3','synthetic-v4'): raise Refused('unknown M04 version')
    root=Path('/usr/local/libexec/opsdrill/m04-'+version)
    manifest=M04_MANIFEST if version=='synthetic-v1' else M04_V4_MANIFEST if version=='synthetic-v4' else M04_V2_MANIFEST
    child=root/'continuation'
    for part in (child,root,*root.parents):
        try: st=part.lstat()
        except OSError as exc: raise Refused('M04 installation missing') from exc
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
            raise Refused('M04 installation is not root-controlled')
    expected_root={name for name in manifest if '/' not in name}|{'continuation'}
    expected_child={name.split('/',1)[1] for name in manifest if '/' in name}
    if set(os.listdir(root))!=expected_root or set(os.listdir(child))!=expected_child:
        raise Refused('unexpected M04 installation files')
    for name,digest in manifest.items():
        fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as stream:
            st=os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode & 0o022 or st.st_size>1048576:
                raise Refused('unsafe M04 module')
            if not m04_digest_matches(name,digest,hashlib.sha256(stream.read(1048577)).hexdigest(),version,action):
                raise Refused('M04 module version mismatch')
    return ['/usr/bin/python3','-I','-B',str(child/'mysql_lifecycle_candidate.py'),action,rid]


def m04_invoke(action,rid,version='synthetic-v1'):
    try:
        cp=subprocess.run(m04_command(action,rid,version),capture_output=True,text=True,check=False,
                          timeout=900 if action=='start' else 420,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
    except subprocess.TimeoutExpired as exc:
        raise Refused('M04 timed out; retain run ID') from exc
    try: obj=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
    except (TypeError,ValueError,Refused): raise Refused('invalid M04 response; retain run ID')
    if not isinstance(obj,dict) or obj.get('run_id')!=rid: raise Refused('invalid M04 response identity')
    status=obj.get('status')
    allowed={'start':('FAULT',), 'check':('FAULT','RECOVERED'), 'resolve':('RECOVERED',), 'reset':('STOPPED',)}
    valid=(set(obj)=={'run_id','status','scope'} and obj.get('scope')=='isolated_socket_only'
           and status in allowed[action] and cp.returncode==(1 if action=='check' and status=='FAULT' else 0))
    if not valid: raise Refused('M04 outcome unconfirmed; retain run ID')
    return obj


def m04_event(state,kind,result,actor,verified=False):
    version=state['m04_version']; rid=state['run_id']; attempt=state['attempt_id']
    if version not in ('synthetic-v1','synthetic-v2','synthetic-v3','synthetic-v4') or not re.fullmatch(r'[0-9a-f]{16}',rid):
        raise Refused('invalid M04 event identity')
    details={'run_id':rid,'m04_version':version}
    if version in ('synthetic-v3','synthetic-v4'):
        details['expected_auditor_sha256']=M04_V2_MANIFEST['pitr_audit.py']
        if verified:
            m04_command('check',rid,version)  # re-check protected runtime after the operation
            details['verified_auditor_sha256']=M04_V2_MANIFEST['pitr_audit.py']
    event('M04',attempt,kind,result,actor,details)


def completed_m04_version(rid):
    """Recover the version only from a protected, completed same-run event history."""
    if not re.fullmatch(r'[0-9a-f]{16}',rid):raise Refused('invalid M04 run ID')
    for part in (EVENT_FILE.parent,*EVENT_FILE.parent.parents):
        st=part.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise Refused('unsafe event directory')
    try:fd=os.open(EVENT_FILE,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    except FileNotFoundError:return 'synthetic-v1'
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>16777216:
            raise Refused('unsafe event file')
        data=b''
        while len(data)<=16777216:
            chunk=os.read(fd,min(65536,16777217-len(data)))
            if not chunk:break
            data+=chunk
        if len(data)!=st.st_size:raise Refused('event file changed')
    finally:os.close(fd)
    try:
        events=[json.loads(line,object_pairs_hook=unique_pairs) for line in data.splitlines()]
    except (ValueError,UnicodeError):raise Refused('invalid event history')
    owned=[x for x in events if isinstance(x,dict) and x.get('drill_id')=='M04' and x.get('run_id')==rid]
    if not owned:return 'synthetic-v1'
    versions={x.get('m04_version') for x in owned};attempts={x.get('attempt_id') for x in owned}
    if (len(versions)!=1 or not versions.issubset({'synthetic-v1','synthetic-v2','synthetic-v3','synthetic-v4'})
            or len(attempts)!=1 or not all(isinstance(x,str) and re.fullmatch(r'M04-[0-9]{8}-[0-9]{6}',x) for x in attempts)
            or not any(x.get('event')=='reset' and x.get('result')=='PASS' for x in owned)):
        raise Refused('M04 completed version is ambiguous')
    return next(iter(versions))


def m04_action(args,state,expected):
    drill='M04'
    if args.command=='start':
        if getattr(args,'variant',None) is not None: raise Refused('M04 does not accept a variant')
        if state: raise Refused('existing state requires reset or inspection')
        attempt=allocate_id(drill); rid=secrets.token_hex(8)
        state={'drill_id':drill,'attempt_id':attempt,'phase':'STARTING','run_id':rid,'m04_version':'synthetic-v4'}
        write_state(drill,state)
        print(json.dumps({'run_id':rid,'status':'STARTING'}),flush=True)
        try:
            m04_event(state,'inject','STARTING',args.actor)
            result=m04_invoke('start',rid,state['m04_version'])
            result=m04_invoke('check',rid,state['m04_version'])
            if result['status']!='FAULT': raise Refused('M04 fault not established')
            state['phase']='ACTIVE'; write_state(drill,state)
            m04_event(state,'inject','PASS',args.actor,verified=True)
            print(json.dumps(result,sort_keys=True)); return 0
        except Exception:
            state['phase']='NEEDS_RESET'; write_state(drill,state)
            m04_event(state,'inject','FAIL',args.actor)
            raise
    if args.command=='reset':
        if state and (state['phase'] not in ('STARTING','ACTIVE','NEEDS_RESET') or state.get('run_id')!=expected):
            raise Refused('ambiguous M04 ownership')
        try:
            if state: m04_event(state,'reset','STARTING',args.actor)
            result=m04_invoke('reset',expected,state['m04_version'] if state else completed_m04_version(expected))
            if state:
                m04_event(state,'reset','PASS',args.actor,verified=True)
                os.unlink(state_path(drill))
            print(json.dumps(result,sort_keys=True)); return 0
        except Exception:
            if state:
                state['phase']='NEEDS_RESET'; write_state(drill,state)
                m04_event(state,'reset','FAIL',args.actor)
            raise
    if args.command in ('check','resolve'):
        if not state or state['phase']!='ACTIVE': raise Refused('no active CLI-owned M04 attempt')
        rid=state['run_id']
        try:
            if args.command=='resolve':
                m04_event(state,'resolve','STARTING',args.actor)
                m04_invoke('resolve',rid,state['m04_version'])
            result=m04_invoke('check',rid,state['m04_version'])
            if args.command=='resolve' and result['status']!='RECOVERED': raise Refused('M04 recovery unconfirmed')
            if args.command=='check':
                m04_event(state,'check','PENDING' if result['status']=='FAULT' else 'PASS',args.actor,verified=True)
            else: m04_event(state,'resolve','PASS',args.actor,verified=True)
            print(json.dumps(result,sort_keys=True))
            return 1 if result['status']=='FAULT' else 0
        except Exception:
            state['phase']='NEEDS_RESET'; write_state(drill,state)
            if args.command=='check': m04_event(state,'check','FAIL',args.actor)
            else: m04_event(state,'resolve','FAIL',args.actor)
            raise
    if args.command in ('hint','note'):
        if not state or state['phase']!='ACTIVE': raise Refused('no active CLI-owned M04 attempt')
        if args.command=='hint':
            hint=secure_file(REGISTRY['M04']+'/hints.md')
            if hint.stat().st_size>16384: raise Refused('hints file too large')
            print(hint.read_text(encoding='utf-8'))
            m04_event(state,'hint','PASS',args.actor)
        else:
            m04_event(state,'diagnosis','PASS',args.actor)
            print('Diagnosis marker recorded; free-form text is not stored.')
        return 0
    raise Refused('unsupported M04 action')


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


# Both normal and CLI entrypoints execute the same root-controlled installation.
M02_MANIFEST = {'m02_deadlock.py': '5d41a8b7feb577b22a358f3497e1a4eb1c53669a1fbf179a49ca9add16c065c9', 'm02_launcher.py': '3d6d8fad99fe5dd0e9ddc85450cb4bb94ae835053cd325d587a9066a418eb11d'}
M02_INSTALL = Path('/usr/local/libexec/opsdrill/m02')
M02_V2_INSTALL = Path('/usr/local/libexec/opsdrill/m02-baseline-v2')
M02_V2_MANIFEST = {'m02_deadlock.py':'11e7e49054d660e521dc5aa0b0c2dab146bd6f9509634d5166e461d83a295b6c','m02_launcher.py':'f0f0550f68b0d38792f42534f6408825c882083afe0e14315e5449d15dd2b2c8'}


def m02_trusted_file(path, digest):
    for component in (path, *path.parents):
        st=component.lstat()
        if st.st_uid!=0 or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
            raise Refused('M02 installation path is not root-controlled')
        if component==path:
            if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>1048576:
                raise Refused('unsafe M02 module')
        elif not stat.S_ISDIR(st.st_mode):
            raise Refused('unsafe M02 installation directory')
    with path.open('rb') as stream:
        if hashlib.sha256(stream.read()).hexdigest()!=digest:
            raise Refused('M02 module version mismatch')


def m02_command(action,rid,require_reset_completed=False,version='legacy'):
    if version not in ('legacy','baseline-v2'): raise Refused('unknown M02 version')
    install,manifest=(M02_INSTALL,M02_MANIFEST) if version=='legacy' else (M02_V2_INSTALL,M02_V2_MANIFEST)
    for name,digest in manifest.items():
        m02_trusted_file(install/name,digest)
    command=['/usr/bin/python3.11','-I','-S','-B',str(install/'m02_launcher.py'),action,'--owned-run-id',rid]
    if require_reset_completed: command.append('--require-reset-completed')
    return command


def m02_action(args,state,expected):
    if args.command=='start':
        if getattr(args,'variant',None) is not None: raise Refused('M02 does not support variants')
        if state: raise Refused('existing state requires reset or inspection')
        rid=secrets.token_hex(12)
        version=getattr(args,'m02_version',None) or 'legacy'
        command=m02_command('inject',rid) if version=='legacy' else m02_command('inject',rid,version=version)
        attempt=allocate_id('M02')
        event('M02',attempt,'inject','STARTING',args.actor)
        state={'drill_id':'M02','attempt_id':attempt,'phase':'STARTING','run_id':rid}
        if version!='legacy': state['m02_version']=version
        write_state('M02',state)
        # The ID is persisted before the subprocess can acquire any DB locks.
        print('M02 run_id:',rid,flush=True)
        try:
            cp=subprocess.run(command,capture_output=True,text=True,check=False)
            if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
            receipt=json.loads(cp.stdout,object_pairs_hook=unique_pairs) if cp.returncode==0 else None
            if cp.returncode==0 and receipt!={'receipt':'M02_DEADLOCK_OWNER_V1','run_id':rid}:
                raise Refused('invalid M02 ownership receipt')
            state['phase']='ACTIVE' if cp.returncode==0 else 'NEEDS_RESET'
            write_state('M02',state)
            event('M02',attempt,'inject','PASS' if cp.returncode==0 else 'FAIL',args.actor)
            return cp.returncode
        except Exception:
            state['phase']='NEEDS_RESET'; write_state('M02',state); raise
    if expected is None: raise Refused('M02 requires --expect-run-id')
    if state and state.get('run_id')!=expected:
        raise Refused('unknown M02 CLI run')
    requested=getattr(args,'m02_version',None)
    version=state.get('m02_version','legacy') if state else requested or 'legacy'
    if requested and requested!=version: raise Refused('M02 version does not match state')
    if args.command=='reset' and state and state['phase'] not in ('STARTING','ACTIVE','NEEDS_RESET'):
        raise Refused('ambiguous M02 ownership')
    try:
        require_done = state is None or (args.command=='check' and state['phase']!='ACTIVE')
        command=m02_command(args.command,expected,require_done) if version=='legacy' else m02_command(args.command,expected,require_done,version=version)
        cp=subprocess.run(command,capture_output=True,text=True,check=False)
        if cp.stdout: print(cp.stdout,end='')
        if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
        if args.command=='reset' and state:
            if cp.returncode==0:
                event('M02',state['attempt_id'],'reset','PASS',args.actor)
                os.unlink(state_path('M02'))
            else:
                state['phase']='NEEDS_RESET'; write_state('M02',state)
                event('M02',state['attempt_id'],'reset','FAIL',args.actor)
        elif args.command=='check' and state:
            event('M02',state['attempt_id'],'check','PASS' if cp.returncode==0 else 'FAIL',args.actor)
        return cp.returncode
    except Exception:
        if args.command=='reset' and state:
            state['phase']='NEEDS_RESET'; write_state('M02',state)
        raise



def c01_event(rid,attempt,kind,result,actor):
    if not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid): raise Refused('invalid C01 event run ID')
    if not isinstance(attempt,str) or not re.fullmatch(r'C01-[0-9]{8}-[0-9]{6}',attempt): raise Refused('invalid C01 event attempt')
    allowed={'inject':('STARTING','PASS'),'check':('PENDING','PARTIAL'),
             'resolve':('MITIGATED',),'reset':('PASS',),'hint':('PASS',),'diagnosis':('PASS',)}
    if kind not in allowed or result not in allowed[kind] or actor not in ('user','agent','unknown'):
        raise Refused('invalid C01 event')
    obj={'drill_id':'C01','attempt_id':attempt,'run_id':rid,'event':kind,'result':result,
         'actor':actor,'ts':datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'boot_id':BOOT_ID.read_text(encoding='ascii').strip(),'monotonic_ns':time.monotonic_ns()}
    fd=os.open(EVENT_FILE,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:
            raise Refused('unsafe events file')
        fcntl.flock(fd,fcntl.LOCK_EX)
        data=(json.dumps(obj,sort_keys=True)+'\n').encode('utf-8')
        view=memoryview(data)
        while view:
            n=os.write(fd,view)
            if n<=0: raise Refused('event write failed')
            view=view[n:]
        os.fsync(fd)
    finally: os.close(fd)
    # Persist a newly created events.jsonl directory entry before injecting.
    fd=os.open(EVENT_FILE.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
            raise Refused('unsafe event directory')
        os.fsync(fd)
    finally: os.close(fd)


def c01_bounded_check(args):
    """Assess a completed agent run using its protected finite-window evidence."""
    rid=getattr(args,'expect_run_id',None)
    directory=getattr(args,'evidence_dir',None)
    digest=getattr(args,'expected_sha256',None)
    if (args.actor!='agent' or not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid)
            or not isinstance(directory,str) or not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest)):
        raise Refused('C01 bounded check needs agent, run ID, evidence directory and digest')
    if read_state('C01') is not None: raise Refused('C01 run is not cleaned')
    cp=c01_call('status','agent',capture=True)
    if cp.returncode: raise Refused('C01 cleanup status unavailable')
    try: status=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
    except (TypeError,ValueError): raise Refused('invalid C01 cleanup status')
    if status!={'status':'CLEANUP_RECORDED','run_id':rid,'actor':'agent','same_boot':True}:
        raise Refused('C01 cleanup does not match run')
    path=secure_file('scripts/audit_c01_window.py')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>131072:raise Refused('invalid C01 auditor')
        data=b''
        while len(data)<=131072:
            chunk=os.read(fd,min(16384,131073-len(data)))
            if not chunk:break
            data+=chunk
    finally:os.close(fd)
    if len(data)!=st.st_size or hashlib.sha256(data).hexdigest()!='da0b2fbd011bc4089d4b47dcb9779c58ecc3fe29dc588c7e6f91472c3583afbe':
        raise Refused('C01 auditor digest mismatch')
    cp=subprocess.run(['/usr/bin/python3','-I','-B','-c',data.decode('utf8'),
        '--run-id',rid,'--evidence-dir',directory,'--expected-sha256',digest],
        capture_output=True,text=True,timeout=120,check=False,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if cp.returncode: raise Refused('C01 bounded evidence rejected')
    try: result=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
    except (TypeError,ValueError): raise Refused('invalid C01 audit output')
    if not isinstance(result,dict) or result.get('status')!='BOUNDED_OBSERVATION_PASS' or result.get('run_id')!=rid or result.get('actor')!='agent' or result.get('result_sha256')!=digest:
        raise Refused('C01 audit identity mismatch')
    print(json.dumps(result,sort_keys=True))
    return 0


def c01_action(args):
    command=args.command
    if command not in ('start','check','resolve','reset','hint','note'):
        raise Refused('unsupported C01 action')
    if getattr(args,'variant',None) is not None or getattr(args,'n04_version',None) is not None:
        raise Refused('unsupported C01 variant')
    expected=getattr(args,'expect_run_id',None)
    if getattr(args,'evidence_dir',None) is not None or getattr(args,'expected_sha256',None) is not None:
        if command!='check': raise Refused('evidence only applies to C01 check')
        return c01_bounded_check(args)
    if command in ('start','hint','note') and expected is not None:
        raise Refused('unexpected run ID')
    if command in ('check','resolve','reset') and (not isinstance(expected,str) or not re.fullmatch(r'[0-9a-f]{24}',expected)):
        raise Refused('C01 requires --expect-run-id')
    state=read_state('C01')
    if command=='start':
        if state: raise Refused('existing C01 CLI state requires inspection')
        try: preflight=c01_call('status',args.actor,capture=True)
        except subprocess.TimeoutExpired as exc: raise Refused('C01 status timed out') from exc
        if preflight.returncode: raise Refused('C01 status unavailable')
        status=json.loads(preflight.stdout,object_pairs_hook=unique_pairs)
        if status!={'status':'NO_RECEIPT'}:
            if not isinstance(status,dict) or set(status)!={'status','run_id','actor','same_boot'} or status.get('status')!='CLEANUP_RECORDED' or not isinstance(status.get('run_id'),str) or not re.fullmatch(r'[0-9a-f]{24}',status['run_id']) or status.get('actor') not in ('user','agent','unknown') or type(status.get('same_boot')) is not bool:
                raise Refused('existing or unverified C01 receipt requires inspection')
        rid=secrets.token_hex(12)
        attempt=allocate_id('C01')
        state={'drill_id':'C01','attempt_id':attempt,'phase':'STARTING','run_id':rid}
        write_state('C01',state)
        # If recording fails, the backend must not be invoked.
        c01_event(rid,attempt,'inject','STARTING',args.actor)
        try:
            cp=c01_call('start',args.actor,rid,capture=True)
            if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
            if cp.returncode:
                state['phase']='NEEDS_RESET'; write_state('C01',state)
                return cp.returncode
            result=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
            if result!={'status':'FAULT_CONFIRMED','run_id':rid,'actor':args.actor,'overall':'INCOMPLETE'}:
                raise Refused('invalid C01 start result')
            c01_event(rid,attempt,'inject','PASS',args.actor)
            state['phase']='ACTIVE'; write_state('C01',state)
            print(cp.stdout,end='')
            return 0
        except subprocess.TimeoutExpired as exc:
            state['phase']='NEEDS_RESET'; write_state('C01',state)
            raise Refused('C01 start timed out; retain run ID') from exc
        except Exception:
            state['phase']='NEEDS_RESET'; write_state('C01',state); raise
    if state is None:
        # A pre-existing or interrupted run without our protected CLI identity
        # remains directly operable by explicit ID, but never gains invented events.
        if command in ('check','resolve','reset'):
            try: return c01_call(command,args.actor,expected).returncode
            except subprocess.TimeoutExpired as exc: raise Refused('C01 operation timed out; retain run ID') from exc
        raise Refused('no C01 CLI-owned attempt')
    rid=state['run_id']; attempt=state['attempt_id']
    if expected is not None and expected!=rid:
        raise Refused('C01 run ID does not match CLI state')
    if command in ('hint','note'):
        if state['phase']!='ACTIVE': raise Refused('no confirmed C01 attempt')
        cp=c01_call('status',args.actor,capture=True)
        if cp.returncode: raise Refused('C01 status unavailable')
        status=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
        if not isinstance(status,dict) or status.get('status')!='RECEIPT_PRESENT_UNVERIFIED' or status.get('run_id')!=rid or status.get('same_boot') is not True:
            raise Refused('C01 receipt does not match CLI state')
        if command=='hint':
            hint=secure_file('drills/capstone/C01/hints.md')
            if hint.stat().st_size>65536: raise Refused('C01 hint too large')
            print(hint.read_text(encoding='utf-8'))
            c01_event(rid,attempt,'hint','PASS',args.actor)
        else:
            if getattr(args,'kind',None)!='diagnosis': raise Refused('unsupported note kind')
            c01_event(rid,attempt,'diagnosis','PASS',args.actor)
            print('Diagnosis marker recorded; free-form text is not stored.')
        return 0
    if command in ('check','resolve') and state['phase']!='ACTIVE':
        raise Refused('C01 start unconfirmed; inspect or reset the bound run')
    try:
        cp=c01_call(command,args.actor,rid,capture=True)
        if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
        try: result=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
        except (TypeError,ValueError): result=None
        if command=='check':
            if cp.returncode==1 and result=={'status':'FAULT_PRESENT','gateway_health':502,'overall':'INCOMPLETE'}:
                observation='FAULT_PRESENT'; event_result='PENDING'
            elif cp.returncode==2 and result=={'status':'RECOVERED_PARTIAL','overall':'INCOMPLETE'}:
                observation='RECOVERED_PARTIAL'; event_result='PARTIAL'
            else:
                raise Refused('C01 check unconfirmed')
            c01_event(rid,attempt,'check',event_result,args.actor)
            state['last_check']=observation; write_state('C01',state)
        elif command=='resolve':
            if cp.returncode!=0 or result!={'status':'MITIGATED','run_id':rid}:
                raise Refused('C01 resolve unconfirmed')
            c01_event(rid,attempt,'resolve','MITIGATED',args.actor)
        else:
            if cp.returncode!=0 or result!={'status':'CLEANUP_PASS','run_id':rid}:
                raise Refused('C01 reset unconfirmed')
            c01_event(rid,attempt,'reset','PASS',args.actor)
            os.unlink(state_path('C01'))
            dfd=os.open(STATE_ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        if cp.stdout: print(cp.stdout,end='')
        return cp.returncode
    except subprocess.TimeoutExpired as exc:
        if command=='reset':
            state['phase']='NEEDS_RESET'; write_state('C01',state)
        raise Refused('C01 operation timed out; retain run ID') from exc
    except Exception:
        if command=='reset':
            state['phase']='NEEDS_RESET'; write_state('C01',state)
        raise


def action(args):
    require_root(); safe_dir()
    lock=open_lock('controller.lock')
    try:
        drill=args.drill
        if drill!='C01' and (getattr(args,'evidence_dir',None) is not None or getattr(args,'expected_sha256',None) is not None): raise Refused('evidence only applies to C01 check')
        if drill!='M02' and getattr(args,'m02_version',None) is not None: raise Refused('M02 version only applies to M02')
        if drill=='C01':
            return c01_action(args)
        if drill not in REGISTRY: raise Refused('drill not registered')
        state=read_state(drill)
        expected=getattr(args,'expect_run_id',None)
        if drill!='N04' and getattr(args,'n04_version',None) is not None: raise Refused('N04 version only applies to N04')
        if expected is not None:
            if not isinstance(expected,str) or not re.fullmatch(r'[0-9a-f]{16}' if drill=='M04' else r'[0-9a-f]{24}',expected): raise Refused('invalid expected run ID')
            # A repeated reset may be a no-op when both CLI and drill are
            # clean, but it must never reset a different current attempt.
            if (not state and args.command!='reset' and not (drill=='M02' and args.command=='check')) or (state and state.get('run_id')!=expected):
                raise Refused('expected run ID does not match current attempt')
        if drill in ('L04','N01','N04','M03','M04') and args.command in ('check','resolve','reset') and expected is None:
            raise Refused(drill+' requires --expect-run-id')
        if drill=='M02' and args.command in ('start','check','reset'):
            return m02_action(args,state,expected)
        if drill=='M03':
            return m03_action(args,state,expected)
        if drill=='M04':
            return m04_action(args,state,expected)
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
            if drill=='L02': state['l02_version']='recovery-v2'
            write_state(drill,state)
            try:
                extra=(variant,) if drill=='L01' else (('--504','--cli') if variant=='504' else ('--cli',)) if drill=='N03' else ()
                if drill=='N04':
                    extra=(state['run_id'],)
                    cp=invoke(drill,'inject',extra,capture=True,n04_version='recovery-v2')
                elif drill=='L02':
                    cp=invoke(drill,'inject',extra,capture=True,l02_version=state['l02_version'])
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
                    if drill=='N03':
                        check=n03_call('verify-owner',owner_args,capture=True)
                    else:
                        if drill=='N04':
                            owner_command=n04_command('check',owner_args,'recovery-v2')
                        elif drill=='L04':
                            owner_command=l04_command('verify-owner',owner_args)
                        elif drill=='M01':
                            owner_command=m01_command('verify-owner',owner_args)
                        elif drill=='L02':
                            owner_command=l02_command('verify-owner',owner_args,state.get('l02_version','legacy'))
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
                cp=invoke(drill,'check',(state['run_id'],),capture=True,l02_version=state.get('l02_version','legacy')) if drill=='L02' else invoke(drill,'check',(state['run_id'],),capture=True)
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
                pending=rc==2 and isinstance(observed,dict) and observed.get('status')=='RUNNING'
                partial=rc==0 and isinstance(observed,dict) and observed.get('status')=='COMPLETED'
                details=None
                if partial and observed.get('run_id')==state['run_id'] and observed.get('unit_active') is False and observed.get('health_current') is True and observed.get('bounded_io_contract')=='PASS':
                    worker=observed.get('worker'); worker=worker if isinstance(worker,dict) else {}
                    obs=worker.get('observation');obs=obs if isinstance(obs,dict) else {}
                    candidate={'run_id':state['run_id'],'l03_contract':'bounded-io-v1','io_evidence':worker.get('io_evidence'),
                               'elapsed_ns':worker.get('elapsed_ns'),'read_bytes':worker.get('read_bytes'),
                               'storage_read_bytes':obs.get('storage_read_bytes'),'health_before':True,'health_after':worker.get('health_ok')}
                    if worker.get('status')=='COMPLETED' and l03_details_valid(candidate):
                        details=candidate;partial=False
                # A scoped pass proves bounded simulation, not hardware failure or global causality.
                if partial or (rc==0 and details is None): rc=2
            else:
                rc=invoke(drill,'check'); pending=False
            result=('PASS' if rc==0 else 'PARTIAL' if partial else 'PENDING' if pending else 'FAIL') if drill=='L03' else ('PASS' if rc==0 else 'PENDING' if pending else 'FAIL')
            if state:
                if drill=='L03' and result=='PASS': event(drill,state['attempt_id'],'check',result,args.actor,details)
                else: event(drill,state['attempt_id'],'check',result,args.actor)
            return rc
        if args.command=='resolve':
            if drill not in ('L04','N01','N04','L02') or not state or state['phase']!='ACTIVE':
                raise Refused('no active CLI-owned attempt')
            try:
                if drill=='N04':
                    cp=invoke(drill,'resolve',(state['run_id'],),capture=True,n04_version=state.get('n04_version','legacy'))
                    if cp.stdout: print(cp.stdout,end='')
                    if cp.stderr: print(cp.stderr,end='',file=sys.stderr)
                    try: rc=0 if n04_resolve_ok(cp,state['run_id']) else 2
                    except Refused: rc=2
                elif drill=='L02':
                    rc=invoke(drill,'resolve',(state['run_id'],),l02_version=state.get('l02_version','legacy'))
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
                    clean=l01_clean() if drill=='L01' else n03_clean() if drill=='N03' else n02_clean() if drill=='N02' else l02_clean(state.get('l02_version','legacy') if state else 'legacy') if drill=='L02' else m01_clean()
                    if clean!=0: raise Refused('ambiguous ownership; inspect the drill directly')
                    if state:
                        event(drill,state['attempt_id'],'reset','CLEAN',args.actor)
                        os.unlink(state_path(drill))
                    return 0
                extra=l01_args(state) if drill=='L01' else (state['run_id'],)
                rc=invoke(drill,'reset',extra,l02_version=state.get('l02_version','legacy')) if drill=='L02' else invoke(drill,'reset',extra)
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
                dfd=os.open(STATE_ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
                try: os.fsync(dfd)
                finally: os.close(dfd)
                event(drill,state['attempt_id'],'reset','CLEAN',args.actor)
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
        if name=='check':
            s.add_argument('--evidence-dir'); s.add_argument('--expected-sha256')
        if name=='reset': s.add_argument('--n04-version',choices=('legacy','recovery-v2'))
        if name in ('start','check','reset'): s.add_argument('--m02-version',choices=('legacy','baseline-v2'))
        if name=='note': s.add_argument('--kind',choices=('diagnosis',),required=True)
    args=p.parse_args(argv)
    if args.command=='list':
        for drill,path in sorted(REGISTRY.items()): print(drill,path)
        print('C01','drills/capstone/C01')
        return 0
    if args.command=='status':
        if os.geteuid()!=0: raise Refused('root required to read protected state')
        try:
            cp=c01_call('status','unknown',capture=True)
            if cp.returncode: raise Refused('C01 status unavailable')
            obj=json.loads(cp.stdout,object_pairs_hook=unique_pairs)
            if not isinstance(obj,dict) or obj.get('status') not in ('NO_RECEIPT','RECEIPT_PRESENT_UNVERIFIED','CLEANUP_RECORDED'):
                raise Refused('invalid C01 status')
            detail=''
            if os.path.lexists(STATE_ROOT):
                safe_dir()
                c01_state=read_state('C01')
                if c01_state:
                    detail='cli_run_id='+c01_state['run_id']+' cli_phase='+c01_state['phase']
                    if obj.get('run_id') and obj['run_id']!=c01_state['run_id']:
                        detail+=' binding=MISMATCH'
                    if c01_state['run_id']==obj.get('run_id') and c01_state.get('last_check'):
                        detail+=' last_check='+c01_state['last_check']
            print('C01',obj['status'],obj.get('run_id',''),detail)
        except (OSError,ValueError,Refused,subprocess.TimeoutExpired):
            print('C01','UNAVAILABLE')
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
