import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

parser=argparse.ArgumentParser(description='Run the auto-owned M02 contract on an authorized lab VM')
parser.add_argument('--m02-version',choices=('legacy','baseline-v2'),default='legacy')
options=parser.parse_args()
cli='/opt/ops-drill-kit/bin/opsdrill'
state_path=Path('/var/lib/opsdrill/cli/M02.json')
def evidence_base(parent=Path('/var')):
    if os.geteuid()!=0:raise RuntimeError('root required for M02 contract')
    for p in (parent,*parent.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('unsafe evidence parent')
    for part in ('backups','opsdrill','M02'):
        parent=parent/part
        try:parent.mkdir(mode=0o700)
        except FileExistsError:pass
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('unsafe evidence directory')
    return parent
stage=evidence_base()/('cli-contract-'+secrets.token_hex(12))
stage.mkdir(mode=0o700)
results=[]
def run(action,rid=None):
    args=[cli,action,'M02','--m02-version',options.m02_version]
    if rid:args+=['--expect-run-id',rid]
    cp=subprocess.run(args,capture_output=True,text=True,timeout=180)
    results.append({'action':action,'returncode':cp.returncode})
    (stage/'contract-results.json').write_text(json.dumps(results,indent=2),encoding='utf8')
    print(action,'exit=',cp.returncode,flush=True)
    return cp
assert not state_path.exists()
started=run('start')
if not state_path.exists():raise SystemExit('No owned M02 state; preserve and inspect')
state=json.loads(state_path.read_text());rid=state.get('run_id')
if state.get('drill_id')!='M02' or not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{24}',rid):
    raise SystemExit('Ambiguous M02 identity; preserve and inspect')
print('M02 owned run:',rid,flush=True)
if started.returncode:
    print('Start not confirmed; state preserved for inspection',flush=True)
    raise SystemExit(2)
assert state['phase']=='ACTIVE'
unknown=secrets.token_hex(12)
assert unknown!=rid
assert run('reset',unknown).returncode != 0
assert run('check',rid).returncode == 0
assert run('reset',rid).returncode == 0
assert not state_path.exists()
assert run('check',rid).returncode == 0
assert run('reset',rid).returncode == 0
assert run('reset',unknown).returncode != 0
print('M02 CLI contract passed:',rid,flush=True)
