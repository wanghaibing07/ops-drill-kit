import argparse
import json
import re
import subprocess
from pathlib import Path

parser=argparse.ArgumentParser(description='M04 v4 controlled stop-interruption contract')
parser.add_argument('--after-stop',action='store_true',help='interrupt after the stop call and before persisting its completion')
options=parser.parse_args()
cli='/opt/ops-drill-kit/bin/opsdrill'
state_path=Path('/var/lib/opsdrill/cli/M04.json')
rid=None
clean=False
reset_attempted=False
def run(*args):
    cp=subprocess.run([cli,*args],capture_output=True,text=True,timeout=900)
    parsed=[]
    for line in cp.stdout.splitlines():
        try:parsed.append(json.loads(line))
        except ValueError:pass
    print(args[0],'rc',cp.returncode,'statuses',[x.get('status') for x in parsed],flush=True)
    return cp,parsed
assert not state_path.exists()
try:
    cp,output=run('start','M04')
    if cp.returncode or not state_path.exists():raise RuntimeError('start unconfirmed; retain state')
    state=json.loads(state_path.read_text())
    assert state.get('drill_id')=='M04' and state.get('phase')=='ACTIVE' and state.get('m04_version')=='synthetic-v4'
    rid=state['run_id'];assert re.fullmatch(r'[0-9a-f]{16}',rid)
    # Simulate loss after durable stop intent, before sending stop to systemd.
    child='''import importlib.util,sys
p='/usr/local/libexec/opsdrill/m04-synthetic-v4/continuation/mysql_lifecycle_candidate.py'
s=importlib.util.spec_from_file_location('m04_intent_probe',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def interrupt(*a,**kw):raise RuntimeError('TEST_INTERRUPT_BEFORE_STOP')
m.ctl.stop_one=interrupt
try:m.existing('reset',sys.argv[1])
except RuntimeError as e:
 if str(e)!='TEST_INTERRUPT_BEFORE_STOP':raise
 print('INTENT_INTERRUPTED_BEFORE_STOP')
else:raise RuntimeError('interruption not reached')
'''
    if options.after_stop:
        old="def interrupt(*a,**kw):raise RuntimeError('TEST_INTERRUPT_BEFORE_STOP')"
        replacement="original_stop=m.ctl.stop_one\ndef interrupt(*a,**kw):\n original_stop(*a,**kw)\n raise RuntimeError('TEST_INTERRUPT_AFTER_STOP')"
        assert child.count(old)==1
        child=child.replace(old,replacement).replace('TEST_INTERRUPT_BEFORE_STOP','TEST_INTERRUPT_AFTER_STOP').replace('INTENT_INTERRUPTED_BEFORE_STOP','INTENT_INTERRUPTED_AFTER_STOP')
    injected=subprocess.run(['/usr/bin/python3','-I','-B','-c',child,rid],capture_output=True,text=True,timeout=150)
    print('injected rc',injected.returncode,'result',injected.stdout.strip(),flush=True)
    if injected.returncode:raise RuntimeError('injected interruption unconfirmed; inspect')
    inspect='''import importlib.util,json,sys
p='/usr/local/libexec/opsdrill/m04-synthetic-v4/continuation/mysql_lifecycle_candidate.py'
s=importlib.util.spec_from_file_location('m04_intent_check',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
d=m.ctl.BASE/sys.argv[1];x=m.ctl.load(d,sys.argv[1]);print(json.dumps({'phase':x.get('candidate_phase'),'intent':x.get('candidate_stopping'),'stopped':x.get('candidate_stopped',[])}))
'''
    check=subprocess.run(['/usr/bin/python3','-I','-B','-c',inspect,rid],capture_output=True,text=True,check=True,timeout=20)
    data=json.loads(check.stdout);print('durable state',data,flush=True)
    assert data=={'phase':'RESETTING','intent':'target','stopped':[]}
    reset_attempted=True
    cp,output=run('reset','M04','--expect-run-id',rid)
    assert cp.returncode==0 and output[-1]['status']=='STOPPED' and not state_path.exists()
    clean=True
    print('M04',('after-stop' if options.after_stop else 'before-stop'),'interruption recovery verified:',rid,flush=True)
finally:
    if rid and not clean and not reset_attempted:
        print('Attempting only identity-bound reset for this run:',rid,flush=True)
        try:run('reset','M04','--expect-run-id',rid)
        except Exception as exc:print('Reset unconfirmed:',type(exc).__name__,flush=True)
