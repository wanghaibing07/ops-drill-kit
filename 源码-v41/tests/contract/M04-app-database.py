import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
import urllib.request

project=Path('/opt/ops-drill-kit');base=Path('/var/backups/opsdrill/M04')
expected={'app/main.py':'0b20304af3f0639598bc5acd67ac342014ff09b6fee7de245dc3e7c507aab9d0',
          'app/stage3_api.py':'4d8d2d1164c1b594795d5fd7c5fb0226165803fa57ccaf194797b3fd56bb3090',
          'app/bounded_pool.py':'c4ede69821d0e5cda20c3fbca020a2b84401a9ce188dc5ed44f0efa025b3a777',
          'conf/orderguard-api.service':'c9362aa8adfcf34cf6ff30f68aedd4aee3416c51be92fc2ec7cf81fcc6ee3983',
          'conf/orderguard-nginx.conf':'e5c190f4703e5917eca726d3679fc4daadabfbbb65c95927732a5a444606f513',
          'conf/00-orderguard-timing.conf':'bcf8e284fd4255874312fd762757737a07af6dceb0490e0c423fe7797709b1b7',
          'requirements.txt':'4631d9507517d44bd1ea9f8b33e7b48d0f25700fc6d0809f97064415ab3cc836'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
helper=project/'scripts/app_backup.py'
assert sha(helper)=='ea1642b12cb8aa8fadd2c18e755bd3fa0393dee714ce48817817486005bafe56'
assert all(sha(project/name)==digest for name,digest in expected.items())
with urllib.request.urlopen('http://127.0.0.1:8080/ready',timeout=5) as response:assert response.status==200
lab=base/('app-db-combined-'+secrets.token_hex(8));lab.mkdir(mode=0o700)
copy=lab/'app_backup.py';copy.write_bytes(helper.read_bytes());os.chmod(copy,0o600)
assert sha(copy)==sha(helper)
spec=importlib.util.spec_from_file_location('reviewed_app_backup_combined',copy)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
(lab/'.opsdrill-lab').write_text('ops-drill-kit\n',encoding='ascii')
for name in ('source','backups','restores'):(lab/name).mkdir(mode=0o700)
for name,digest in expected.items():
    src=project/name
    assert not src.is_symlink() and src.is_file()
    data=src.read_bytes();assert hashlib.sha256(data).hexdigest()==digest
    dst=lab/'source'/name;dst.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with dst.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    os.chmod(dst,stat.S_IMODE(src.stat().st_mode)&0o777)
backup=mod.backup(lab,'source','backups/run',tuple(expected))
cli=str(project/'bin/opsdrill');rid=None;clean=False
def run(action,run_id=None):
    args=[cli,action,'M04']
    if run_id:args+=['--expect-run-id',run_id]
    cp=subprocess.run(args,capture_output=True,text=True,timeout=900)
    output=[]
    for line in cp.stdout.splitlines():
        try:output.append(json.loads(line))
        except ValueError:pass
    print(action,'rc',cp.returncode,'statuses',[x.get('status') for x in output],flush=True)
    return cp,output
try:
    cp,items=run('start')
    assert cp.returncode==0 and items[-1].get('status')=='FAULT'
    rid=items[-1]['run_id'];assert re.fullmatch(r'[0-9a-f]{16}',rid)
    cp,items=run('resolve',rid);assert cp.returncode==0 and items[-1].get('status')=='RECOVERED'
    restored=mod.restore(lab,'backups/run','restores/run')
    for name,digest in expected.items():
        assert sha(project/name)==digest and sha(restored/name)==digest
        assert stat.S_IMODE((lab/'source'/name).stat().st_mode)==stat.S_IMODE((restored/name).stat().st_mode)
    cp,items=run('check',rid);assert cp.returncode==0 and items[-1].get('status')=='RECOVERED'
    cp,items=run('reset',rid);assert cp.returncode==0 and items[-1].get('status')=='STOPPED'
    clean=True
    with urllib.request.urlopen('http://127.0.0.1:8080/ready',timeout=5) as response:assert response.status==200
    result={'status':'PASS','run_id':rid,'files':len(expected),'manifest_sha256':sha(backup/'manifest.json'),
            'scope':'selected non-secret app files and isolated synthetic database; not a coordinated production snapshot',
            'time_ns':time.time_ns()}
    with (lab/'result.json').open('x',encoding='utf8') as f:json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
    print('M04 synthetic database and selected application file restore verified:',rid,lab,flush=True)
finally:
    if rid and not clean:
        print('Attempt identity-bound reset',rid,flush=True)
        try:run('reset',rid)
        except Exception as exc:print('Reset unconfirmed:',type(exc).__name__,flush=True)
