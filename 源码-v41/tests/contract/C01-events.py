import json
import subprocess
import sys
import urllib.request

cli='/opt/ops-drill-kit/bin/opsdrill'
rid=None
cleaned=False
def cmd(*args):
    cp=subprocess.run([cli,*args],capture_output=True,text=True,timeout=130)
    print(args[0], 'rc=',cp.returncode, 'output=',cp.stdout.strip()[:500], 'error=',cp.stderr.strip()[:300],flush=True)
    return cp
def call(action,rid):return cmd(action,'C01','--expect-run-id',rid)
try:
    result=cmd('start','C01')
    assert result.returncode==0,'start not confirmed; retain state for inspection'
    obj=json.loads(result.stdout)
    assert obj['status']=='FAULT_CONFIRMED' and len(obj['run_id'])==24
    rid=obj['run_id']
    fault=call('check',rid)
    assert fault.returncode==1 and json.loads(fault.stdout)['status']=='FAULT_PRESENT'
    wrong=call('check','0'*24)
    assert wrong.returncode!=0
    note=cmd('note','C01','--kind','diagnosis')
    assert note.returncode==0
    fix=call('resolve',rid)
    assert fix.returncode==0 and json.loads(fix.stdout)['status']=='MITIGATED'
    check=call('check',rid)
    assert check.returncode==2 and json.loads(check.stdout)['status']=='RECOVERED_PARTIAL'
    reset=call('reset',rid)
    assert reset.returncode==0 and json.loads(reset.stdout)['status']=='CLEANUP_PASS'
    cleaned=True
    repeated=call('reset',rid)
    assert repeated.returncode!=0 and 'RUN_ALREADY_CLEANED' in repeated.stderr
    report=subprocess.run(['/usr/bin/python3','-B','/opt/ops-drill-kit/scripts/report.py'],capture_output=True,text=True,check=True)
    data=json.loads(report.stdout)
    rows=[x for x in data['attempts'] if x.get('run_id')==rid]
    assert len(rows)==1 and rows[0]['status']=='PARTIAL' and rows[0]['mttr_proxy_seconds'] is None
    print('C01 report:',json.dumps(rows[0],ensure_ascii=False),'invalid_lines=',data['invalid_lines'],flush=True)
    with urllib.request.urlopen('http://127.0.0.1:8080/ready',timeout=5) as response:assert response.status==200
    print('Ready endpoint 200; event lifecycle verified',flush=True)
finally:
    if rid and not cleaned:
        print('Attempting identity-bound cleanup for this run',rid,flush=True)
        call('reset',rid)
