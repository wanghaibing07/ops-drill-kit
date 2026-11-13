import json, os, pathlib, secrets, subprocess, sys
controller='/usr/local/libexec/opsdrill/m03-candidate/mysql_lifecycle.py'
rid=secrets.token_hex(12)
evidence=pathlib.Path('/var/backups/opsdrill/M03')/('lifecycle-'+rid)
evidence.mkdir(mode=0o700)
(evidence/'run_id').write_text(rid+'\n');os.chmod(evidence/'run_id',0o600)
print('M03 isolated candidate run:',rid,flush=True)
counter=0
def action(name,expected_rc,expected_status):
 global counter
 counter+=1
 p=subprocess.run(['/usr/bin/python3','-I','-B',controller,name,rid],capture_output=True,text=True,timeout=620 if name=='start' else 200)
 prefix=f'{counter:02d}-{name}'
 (evidence/(prefix+'.stdout')).write_text(p.stdout);(evidence/(prefix+'.stderr')).write_text(p.stderr)
 for q in (evidence/(prefix+'.stdout'),evidence/(prefix+'.stderr')):os.chmod(q,0o600)
 print(name,'rc=',p.returncode,'response=',p.stdout.strip(),flush=True)
 if p.returncode!=expected_rc: raise RuntimeError(name+' unexpected exit')
 obj=json.loads(p.stdout)
 if obj.get('run_id')!=rid or obj.get('status')!=expected_status:raise RuntimeError(name+' unconfirmed')
 return obj
try:
 action('start',0,'READY')
 action('inject',0,'INJECTED')
 fault=action('check',1,'FAULT');assert fault.get('mysql_error')==1040 and fault.get('sleep_connections')==8
 action('resolve',0,'RELEASED')
 recovery=action('check',0,'RECOVERED');assert recovery.get('connection')=='OK' and recovery.get('sleep_connections')==0
 action('reset',0,'STOPPED')
 action('reset',0,'STOPPED')
 print('M03 actual lifecycle passed; evidence:',evidence,flush=True)
except Exception:
 print('M03 run incomplete; retain and inspect:',rid,'evidence:',evidence,file=sys.stderr,flush=True)
 try: action('reset',0,'STOPPED')
 except Exception: print('Owned reset not confirmed; inspect retained state.',file=sys.stderr,flush=True)
 raise
