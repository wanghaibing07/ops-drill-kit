import json
import re
import secrets
import subprocess
import sys
from pathlib import Path

cli='/opt/ops-drill-kit/bin/opsdrill'
state_path=Path('/var/lib/opsdrill/cli/M03.json')
stage=Path('/var/backups/opsdrill/M03')/('cli-contract-'+secrets.token_hex(12))
stage.mkdir(mode=0o700)
records=[]

def run(action, rid=None, timeout=420):
    argv=[cli,action,'M03']
    if rid: argv+=['--expect-run-id',rid]
    result=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    records.append({'action':action,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
    (stage/'cli-contract-results.json').write_text(json.dumps(records,indent=2),encoding='utf8')
    print(action,'rc=',result.returncode,'stdout=',result.stdout.strip(),'stderr=',result.stderr.strip(),flush=True)
    return result

assert not state_path.exists()
first=run('start',timeout=780)
if not state_path.exists(): raise SystemExit('No owned M03 state; inspect before further action')
state=json.loads(state_path.read_text())
rid=state.get('run_id')
if state.get('drill_id')!='M03' or not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{24}',rid):
    raise SystemExit('Ambiguous M03 state; preserve and inspect')
if first.returncode:
    print('Start failed; attempting reset for recorded run only',rid,flush=True)
    run('reset',rid)
    raise SystemExit('M03 start was not verified')
assert state['phase']=='ACTIVE'
unknown=secrets.token_hex(12)
assert unknown!=rid and not (Path('/run/opsdrill-m03-mysql')/unknown).exists()
assert run('reset',unknown).returncode != 0
fault=run('check',rid)
assert fault.returncode==1 and json.loads(fault.stdout)['mysql_error']==1040
assert run('resolve',rid).returncode==0
recovered=run('check',rid)
assert recovered.returncode==0 and json.loads(recovered.stdout)['status']=='RECOVERED'
assert run('reset',rid).returncode==0
assert not state_path.exists()
assert run('reset',rid).returncode==0
assert run('reset',unknown).returncode!=0
print('M03 CLI full normal contract passed for',rid,flush=True)
