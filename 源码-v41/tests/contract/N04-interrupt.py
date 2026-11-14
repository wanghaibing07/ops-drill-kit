import json, os, pathlib, signal, subprocess, sys, time
root=pathlib.Path('/opt/ops-drill-kit')
state=pathlib.Path('/var/lib/opsdrill/cli/N04.json')
assert not state.exists()
cmd=[str(root/'bin/opsdrill'),'start','N04']
child=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
rid=None; stopped=False; killed=False
try:
 deadline=time.monotonic()+15
 while time.monotonic()<deadline:
  if child.poll() is not None: raise RuntimeError('start completed before interruption point')
  try:
   x=json.loads(state.read_text()); candidate=x.get('run_id')
   if x.get('phase')=='STARTING' and x.get('n04_version')=='recovery-v2' and candidate and (pathlib.Path('/run/opsdrill-n04-recovery-v2')/candidate/'intent.json').exists():
    rid=candidate; break
  except (FileNotFoundError,ValueError): pass
  time.sleep(.01)
 if not rid: raise RuntimeError('intent not observed in time')
 os.kill(child.pid,signal.SIGSTOP);stopped=True
 deadline=time.monotonic()+20
 record=pathlib.Path('/run/opsdrill-n04-recovery-v2')/rid/'identity.json'
 while time.monotonic()<deadline and not record.exists(): time.sleep(.05)
 if not record.exists(): raise RuntimeError('identity not created during pause')
 x=json.loads(state.read_text()); assert x['phase']=='STARTING' and x['run_id']==rid
 os.kill(child.pid,signal.SIGKILL);killed=True;stopped=False
 child.wait(timeout=5)
 result=subprocess.run([str(root/'bin/opsdrill'),'reset','N04','--expect-run-id',rid],capture_output=True,text=True,timeout=15)
 print(result.stdout,end='');print(result.stderr,end='',file=sys.stderr)
 assert result.returncode==0 and not state.exists()
 response=json.loads(result.stdout);assert response['run_id']==rid and response['service_stopped'] is True
 print('N04 real CLI interruption recovered:',rid)
except Exception:
 print('N04 interruption incomplete; retain and inspect run:',rid,file=sys.stderr)
 raise
finally:
 if stopped and child.poll() is None:
  os.kill(child.pid,signal.SIGCONT)
 if not killed and child.poll() is None:
  try: child.wait(timeout=35)
  except subprocess.TimeoutExpired: print('Owned CLI still running; inspect before any action',file=sys.stderr)
