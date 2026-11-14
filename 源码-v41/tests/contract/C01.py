import json
import secrets
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

cli='/opt/ops-drill-kit/bin/opsdrill'
stage=Path('/var/backups/opsdrill/C01')/('contract-'+secrets.token_hex(12))
stage.mkdir(mode=0o700)
results=[]
def http(path):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8080'+path,timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as exc:return exc.code
def run(action,rid=None):
    args=[cli,action,'C01']
    if rid:args+=['--expect-run-id',rid]
    cp=subprocess.run(args,capture_output=True,text=True,timeout=120)
    try: obj=json.loads(cp.stdout)
    except ValueError: obj={}
    results.append({'action':action,'returncode':cp.returncode,'response':obj})
    (stage/'results.json').write_text(json.dumps(results,indent=2),encoding='utf8')
    print(action,'rc=',cp.returncode,'status=',obj.get('status'),flush=True)
    return cp,obj
assert http('/orders/1001')==200 and http('/health')==200
started,obj=run('start')
if started.returncode or obj.get('status')!='FAULT_CONFIRMED':
    raise SystemExit('C01 start not confirmed; preserve receipt and inspect')
rid=obj['run_id'];print('C01 run:',rid,flush=True)
bad=secrets.token_hex(12)
assert bad!=rid and run('reset',bad)[0].returncode!=0
fault,body=run('check',rid)
assert fault.returncode==1 and body.get('status')=='FAULT_PRESENT'
fault_order=http('/orders/1001');print('fault order HTTP',fault_order,flush=True)
assert fault_order==502
assert run('resolve',rid)[0].returncode==0
recovered,body=run('check',rid)
assert recovered.returncode==2 and body.get('status')=='RECOVERED_PARTIAL'
assert http('/orders/1001')==200 and http('/health')==200 and http('/ready')==200
assert run('reset',rid)[0].returncode==0
assert http('/orders/1001')==200 and http('/ready')==200
print('C01 order gateway fault and service recovery observed:',rid,flush=True)
