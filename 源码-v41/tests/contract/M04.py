import json
import re
import secrets
import subprocess
from pathlib import Path

cli='/opt/ops-drill-kit/bin/opsdrill'
state_path=Path('/var/lib/opsdrill/cli/M04.json')
stage=Path('/var/backups/opsdrill/M04')/('cli-contract-'+secrets.token_hex(12))
stage.mkdir(mode=0o700)
steps=[]
def run(action,rid=None):
    args=[cli,action,'M04']
    if rid:args+=['--expect-run-id',rid]
    args+=['--actor','agent']
    cp=subprocess.run(args,capture_output=True,text=True,timeout=300)
    outputs=[]
    for line in cp.stdout.splitlines():
        try:outputs.append(json.loads(line))
        except ValueError:pass
    steps.append({'action':action,'returncode':cp.returncode,'responses':outputs})
    (stage/'results.json').write_text(json.dumps(steps,indent=2),encoding='utf8')
    print(action,'rc=',cp.returncode,'statuses=',[x.get('status') for x in outputs],flush=True)
    return cp,outputs
assert not state_path.exists()
start,outputs=run('start')
if not state_path.exists():raise SystemExit('No owned M04 state; inspect before further action')
state=json.loads(state_path.read_text());rid=state.get('run_id')
if state.get('drill_id')!='M04' or not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{16}',rid):
    raise SystemExit('M04 identity ambiguous; preserve state')
print('M04 CLI run:',rid,flush=True)
if start.returncode:
    print('Start failed; preserve same-run state and inspect',flush=True)
    raise SystemExit(2)
assert state['phase']=='ACTIVE' and outputs[-1].get('status')=='FAULT'
wrong=secrets.token_hex(8)
assert wrong!=rid and run('reset',wrong)[0].returncode!=0
cp,out=run('check',rid);assert cp.returncode==1 and out[-1].get('status')=='FAULT'
cp,out=run('resolve',rid);assert cp.returncode==0 and out[-1].get('status')=='RECOVERED'
cp,out=run('check',rid);assert cp.returncode==0 and out[-1].get('status')=='RECOVERED'
cp,out=run('reset',rid);assert cp.returncode==0 and out[-1].get('status')=='STOPPED'
assert not state_path.exists()
cp,out=run('reset',rid);assert cp.returncode==0 and out[-1].get('status')=='STOPPED'
assert run('reset',wrong)[0].returncode!=0
print('M04 unified CLI contract passed:',rid,flush=True)
