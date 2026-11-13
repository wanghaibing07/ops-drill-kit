import json
import subprocess
import sys

root='/usr/local/libexec/opsdrill/l02-recovery-v2'
sys.path.insert(0,root)
import l02_prepare as prep
from l02_linux_journal import Journal

rid=None
original=prep.start
def interrupted(*args,**kwargs):
    global rid
    rid=original(*args,**kwargs)
    print('owned run',rid,flush=True)
    raise RuntimeError('TEST_INTERRUPT_BEFORE_INVOCATION_SAVE')
prep.start=interrupted
try:
    prep.prepare(19081,8443)
    raise RuntimeError('expected interruption not reached')
except RuntimeError as exc:
    if str(exc)!='TEST_INTERRUPT_BEFORE_INVOCATION_SAVE':raise
assert rid is not None
j=Journal(create=False)
try:
    with j.locked():record=j.read(rid)
finally:j.close()
assert record['phase']=='PREPARED' and record.get('invocation') is None and record.get('launch_intent',{}).get('token')
print('journal PREPARED; launch identity saved; invocation not yet saved',flush=True)
helper=subprocess.run(['/usr/bin/python3','-I','-B',root+'/l02_watchdog_helper.py',rid],capture_output=True,text=True,timeout=45)
print('watchdog rc',helper.returncode,'result',helper.stdout.strip(),'error',helper.stderr.strip(),flush=True)
if helper.returncode:raise RuntimeError('watchdog refused; retain resources and inspect')
j=Journal(create=False)
try:
    with j.locked():record=j.read(rid)
finally:j.close()
assert record['phase']=='NEEDS_REVIEW' and record.get('watchdog_status')=='STOPPED_OR_ABSENT' and record.get('invocation')
print('watchdog bound invocation and preserved stopped record',flush=True)
shim="import runpy,sys;sys.path.insert(0,"+repr(root)+");runpy.run_path("+repr(root+'/l02_cli.py')+",run_name='__main__')"
reset=subprocess.run(['/usr/bin/python3','-I','-B','-c',shim,'reset',rid],capture_output=True,text=True,timeout=90)
print('reset rc',reset.returncode,'result',reset.stdout.strip(),'error',reset.stderr.strip(),flush=True)
if reset.returncode:raise RuntimeError('identity-bound reset unconfirmed; retain state')
check=subprocess.run(['/usr/bin/python3','-I','-B','-c',shim,'inspect-clean'],capture_output=True,text=True,timeout=30)
print('clean rc',check.returncode,'result',check.stdout.strip(),flush=True)
assert check.returncode==0
print('L02 prewrite interruption recovered:',rid,flush=True)
