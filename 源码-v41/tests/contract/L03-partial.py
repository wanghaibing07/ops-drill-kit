#!/usr/bin/env python3
"""Run bounded L03 and verify scoped evidence plus identity-bound cleanup."""
import json,re,subprocess,sys,time
from pathlib import Path

CLI='/opt/ops-drill-kit/bin/opsdrill'
def run(action,run_id=None):
    args=[CLI,action,'L03']
    if run_id:args+=['--expect-run-id',run_id]
    cp=subprocess.run(args,capture_output=True,text=True,timeout=45)
    try:obj=json.loads(cp.stdout)
    except ValueError:obj={}
    print(action,'rc',cp.returncode,'status',obj.get('status'),flush=True)
    return cp,obj

def main():
    rid=None;clean=False
    try:
        cp,receipt=run('start')
        if cp.returncode!=0 or receipt.get('receipt')!='L03_RUN_OWNER_V1':raise RuntimeError('start not confirmed; retain state')
        rid=receipt.get('run_id')
        if not isinstance(rid,str) or not re.fullmatch(r'[0-9a-f]{24}',rid):raise RuntimeError('invalid run identity')
        state=json.loads(Path('/var/lib/opsdrill/cli/L03.json').read_text())
        if state.get('run_id')!=rid or state.get('phase')!='ACTIVE':raise RuntimeError('CLI ownership mismatch')
        attempt=state['attempt_id'];deadline=time.monotonic()+35
        while True:
            cp,obj=run('check',rid)
            if obj.get('status')!='RUNNING':break
            if time.monotonic()>=deadline:raise RuntimeError('workload deadline exceeded')
            time.sleep(.5)
        if obj.get('status')!='COMPLETED' or obj.get('run_id')!=rid or obj.get('health_current') is not True:
            raise RuntimeError('bounded workload not confirmed')
        scoped=cp.returncode==0 and obj.get('bounded_io_contract')=='PASS'
        if not scoped and cp.returncode!=2:raise RuntimeError('unexpected L03 check result')
        cp,reset=run('reset',rid)
        if cp.returncode!=0 or reset.get('status')!='CLEANUP_PASS' or reset.get('run_id')!=rid:raise RuntimeError('cleanup not confirmed')
        clean=True
        if not scoped:
            print('L03 workload and cleanup verified; controlled I/O evidence remains PARTIAL:',rid,flush=True)
            return 2
        report_path=Path(CLI).resolve().parent.parent/'scripts/report.py'
        report=subprocess.run(['/usr/bin/python3','-I','-B',str(report_path)],capture_output=True,text=True,timeout=30,check=True)
        rows=[x for x in json.loads(report.stdout)['attempts'] if x.get('drill_id')=='L03' and x.get('attempt_id')==attempt]
        if len(rows)!=1 or rows[0].get('status')!='PASS' or rows[0].get('scope')!='bounded_io_simulation' or rows[0].get('mttr_proxy_seconds') is not None:
            raise RuntimeError('scoped report or cleanup evidence unconfirmed')
        print('L03 controlled I/O simulation contract PASS; hardware fault not asserted:',rid,flush=True)
        return 0
    finally:
        if rid and not clean:
            print('Attempting only identity-bound L03 cleanup:',rid,flush=True)
            try:run('reset',rid)
            except Exception as exc:print('cleanup unconfirmed:',type(exc).__name__,flush=True)

if __name__=='__main__':sys.exit(main())
