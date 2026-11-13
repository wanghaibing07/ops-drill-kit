import argparse,base64,hashlib,importlib.util,json,os,pwd,re,secrets,socket,stat,subprocess,time,urllib.error,urllib.request,zlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--vm-uuid',required=True);p.add_argument('--source-root',required=True);a=p.parse_args()
assert os.geteuid()==0 and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==a.vm_uuid
root=Path(a.source_root);assert root.is_absolute();cli=root/'bin/opsdrill'
pins={'app/main.py':'c66ec5b96019ed02293d676f2d66aeada60ab51765fbe2a2f2bab0dca7b77126','app/stage3_api.py':'1b1de2012ad6402bcd8e54edc3ac71014663153487c017367833aa83a9f07334','app/n03_slow.py':'2efb68db6aad54239b2c0fd42b85fae9947b87ff7ac20c712b41afeef9cdae99','app/bounded_pool.py':'d03cfece4535af585288a64e1d027d3488b1cb447bc191033494b04cf45b2747','conf/orderguard-api.service':'c9362aa8adfcf34cf6ff30f68aedd4aee3416c51be92fc2ec7cf81fcc6ee3983','conf/orderguard-nginx.conf':'e5c190f4703e5917eca726d3679fc4daadabfbbb65c95927732a5a444606f513','conf/00-orderguard-timing.conf':'bcf8e284fd4255874312fd762757737a07af6dceb0490e0c423fe7797709b1b7','requirements.txt':'4631d9507517d44bd1ea9f8b33e7b48d0f25700fc6d0809f97064415ab3cc836','scripts/app_backup.py':'ea1642b12cb8aa8fadd2c18e755bd3fa0393dee714ce48817817486005bafe56','scripts/opsdrill_cli.py':'8edac648dc7ad06dd9b23029723f3bb0513d18539f75ddc8803ec57c69e04722','bin/opsdrill':'5976790b5f19433e51179c902518d873e8cba4bcb77d7cc8fe9abf2077f70e43'}
for d in (root/'app',root/'conf',root/'scripts',root/'bin',root,*root.parents):
 s=d.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
contents={}
for name,digest in pins.items():
 fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:s=os.fstat(f.fileno());data=f.read(1048577)
 assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022 and hashlib.sha256(data).hexdigest()==digest
 contents[name]=(data,stat.S_IMODE(s.st_mode))
u=pwd.getpwnam('devops');env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
assert not os.path.lexists('/var/lib/opsdrill/cli/M04.json')
mem={x.split(':',1)[0]:int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')};assert mem.get('MemAvailable',0)>=512*1024
q=subprocess.run(['/opt/ops-drill-kit/.venv/bin/python','-I','-B','-c','import fastapi,uvicorn,pymysql'],user=u.pw_uid,group=u.pw_gid,extra_groups=[],env=env,capture_output=True,timeout=15);assert q.returncode==0
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(url):
 try:r=opener.open(url,timeout=8)
 except urllib.error.HTTPError as e:r=e
 with r:
  body=r.read(65537);assert len(body)<=65536
  try:data=json.loads(body)
  except (ValueError,UnicodeError):data={}
  return r.status,data
assert get('http://127.0.0.1:8080/ready')[0]==200
base=Path('/var/backups/opsdrill/M04')
for d in (base,*base.parents):
 s=d.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
resultdir=base/('app-db-live-'+secrets.token_hex(8));resultdir.mkdir(mode=0o700)
lab=Path('/var/tmp')/('opsdrill-m04-app-'+secrets.token_hex(8));lab.mkdir(mode=0o750);os.chown(lab,0,u.pw_gid);os.chmod(lab,0o750)
(lab/'.opsdrill-lab').write_text('ops-drill-kit\n',encoding='ascii')
for name in ('source','backups','restores'):(lab/name).mkdir(mode=0o700)
os.chown(lab/'restores',0,u.pw_gid);os.chmod(lab/'restores',0o750)
names=[x for x in pins if x.startswith('app/') or x.startswith('conf/') or x=='requirements.txt']
for name in names:
 data,mode=contents[name];path=lab/'source'/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);os.fchmod(f.fileno(),mode);f.flush();os.fsync(f.fileno())
spec=importlib.util.spec_from_file_location('reviewed_app_backup',root/'scripts/app_backup.py');backupmod=importlib.util.module_from_spec(spec);spec.loader.exec_module(backupmod)
backup=backupmod.backup(lab,'source','backups/run',names);restored=backupmod.restore(lab,'backups/run','restores/run')
for name in names:
 data,mode=contents[name];path=restored/name
 assert hashlib.sha256(path.read_bytes()).hexdigest()==pins[name] and stat.S_IMODE(path.stat().st_mode)==mode
for d in (restored,restored/'app'):
 os.chown(d,0,u.pw_gid);os.chmod(d,0o750)
helpers=Path(__file__).absolute().parent
for d in (helpers,*helpers.parents):
 st=d.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
helper_pins={'m04-app-proxy.py': 'd30cfebb00aafc316d15b22b3fe3da471571d503dbfd6f01a4d8f49570d282fd', 'm04-restored-app-server.py': 'd6995c70ff0d8fc32598d8a5fe4e6bfffe2f2dc6c7a518d920c70e6077722b5e'}
helper_data=[]
for name,digest in helper_pins.items():
 fd=os.open(helpers/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:st=os.fstat(f.fileno());data=f.read(1048577)
 assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022 and hashlib.sha256(data).hexdigest()==digest
 helper_data.append(data)
for name,data in zip(('proxy.py','server.py'),helper_data):
 fd=os.open(lab/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
 with os.fdopen(fd,'wb') as f:f.write(data);os.fchown(f.fileno(),0,u.pw_gid);os.fchmod(f.fileno(),0o640);f.flush();os.fsync(f.fileno())
spec=importlib.util.spec_from_file_location('reviewed_cli',root/'scripts/opsdrill_cli.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
rid=None;started=False;attempted=False;account_clean=True;clean=False;api=None;proxy=None;listener=None;result=None;m=None
def action(name,rid=None):
 argv=[str(cli),name,'M04','--actor','agent']
 if rid:argv+=['--expect-run-id',rid]
 q=subprocess.run(argv,capture_output=True,text=True,timeout=145,env=env);items=[]
 for line in q.stdout.splitlines():
  try:items.append(json.loads(line))
  except ValueError:pass
 print('M04',name,'exit',q.returncode,flush=True)
 return q,items
def terminate(proc,name):
 if proc is not None and proc.poll() is None:
  proc.terminate()
  try:proc.wait(timeout=15)
  except subprocess.TimeoutExpired:raise RuntimeError(name+' did not stop; preserve state')
def target_state():
 directory=m.ctl.BASE/rid;state=m.ctl.load(directory,rid);m.records_from_state(rid,state)
 assert state.get('phase')=='READY' and state.get('candidate_phase') in ('FAULT','RECOVERED')
 return state
def target_sql(statement):
 state=target_state()
 with m.guarded(rid,state):
  m.ctl.verify(rid,'target',state['primary_uuid'],state['uuids']['target'])
  return m.ctl.sql(rid,'target',statement)
try:
 q,items=action('start');statefile=Path('/var/lib/opsdrill/cli/M04.json')
 if q.returncode or not statefile.exists():raise RuntimeError('start unconfirmed; preserve state')
 state=json.loads(statefile.read_text());rid=state.get('run_id')
 assert state.get('drill_id')=='M04' and state.get('phase')=='ACTIVE' and state.get('m04_version')=='synthetic-v4' and re.fullmatch('[0-9a-f]{16}',rid)
 started=True;v.m04_command('check',rid,'synthetic-v4')
 module=Path('/usr/local/libexec/opsdrill/m04-synthetic-v4/continuation/mysql_lifecycle_candidate.py')
 spec=importlib.util.spec_from_file_location('verified_m04_lifecycle',module);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 q,items=action('check',rid);assert q.returncode==1 and items[-1].get('status')=='FAULT'
 state=target_state();sock=m.ctl.paths(rid,'target')[2];st=sock.lstat();assert stat.S_ISSOCK(st.st_mode)
 account='m04_read_'+secrets.token_hex(8);marker=secrets.token_hex(32)
 intent={'run_id':rid,'account':account,'status':'CREATE_ATTEMPTED'}
 with (resultdir/'account-intent.json').open('x',encoding='utf-8') as f:json.dump(intent,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 assert target_sql("SELECT COUNT(*) FROM mysql.user WHERE User='"+account+"' AND Host='localhost'")=='0'
 attempted=True;account_clean=False
 target_sql("CREATE USER '"+account+"'@'localhost' IDENTIFIED BY '"+marker+"'; GRANT SELECT ON `orderguard_restore_m04`.`orders` TO '"+account+"'@'localhost';")
 grants=target_sql("SHOW GRANTS FOR '"+account+"'@'localhost'").splitlines()
 assert len(grants)==2 and sum(x.startswith('GRANT USAGE ON *.* TO ') for x in grants)==1 and sum(x.startswith('GRANT SELECT ON `orderguard_restore_m04`.`orders` TO ') for x in grants)==1
 path=lab/'proxy.sock';proxy=subprocess.Popen(['/usr/bin/python3','-I','-B',str(lab/'proxy.py'),str(path),str(sock),str(st.st_dev),str(st.st_ino),str(u.pw_uid),str(u.pw_gid)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,start_new_session=True)
 deadline=time.monotonic()+10
 while not path.exists():
  assert proxy.poll() is None and time.monotonic()<deadline;time.sleep(.1)
 st=path.lstat();assert stat.S_ISSOCK(st.st_mode) and st.st_uid==0 and st.st_gid==u.pw_gid and stat.S_IMODE(st.st_mode)==0o660
 listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);listener.bind(('127.0.0.1',0));listener.listen(16);port=listener.getsockname()[1]
 appenv=dict(env,M04_APP_SOURCE=str(restored),M04_PROXY_SOCKET=str(path),M04_TEST_USER=account,M04_TEST_MARKER=marker,M04_HTTP_FD=str(listener.fileno()))
 api=subprocess.Popen(['/opt/ops-drill-kit/.venv/bin/python','-I','-B',str(lab/'server.py')],user=u.pw_uid,group=u.pw_gid,extra_groups=[],pass_fds=(listener.fileno(),),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=appenv,start_new_session=True)
 listener.close();listener=None;url='http://127.0.0.1:'+str(port);deadline=time.monotonic()+15
 while True:
  assert api.poll() is None and proxy.poll() is None and time.monotonic()<deadline
  try:
   code,body=get(url+'/health')
   if code==200 and body.get('status')=='ok':break
  except (OSError,urllib.error.URLError):time.sleep(.1)
 assert get(url+'/ready')[0]==200
 code,before=get(url+'/api/v1/orders?merchant_id=88&page_size=10');assert code==200 and before['total']==2
 rows={x['order_no']:x['amount_cents'] for x in before['items']};assert rows=={'m04-synthetic-a':100,'m04-synthetic-b':200}
 code,metrics=get(url+'/__opsdrill/pool-metrics');assert code==200 and metrics['pid']==api.pid;generation=metrics['stage3']['generation']
 q,items=action('resolve',rid);assert q.returncode==0 and items[-1].get('status')=='RECOVERED'
 q,items=action('check',rid);assert q.returncode==0 and items[-1].get('status')=='RECOVERED'
 code,after=get(url+'/api/v1/orders?merchant_id=88&page_size=10');assert code==200 and after['total']==2
 rows={x['order_no']:x['amount_cents'] for x in after['items']};assert rows=={'m04-synthetic-a':101,'m04-synthetic-b':200}
 assert get(url+'/ready')[0]==200
 code,metrics2=get(url+'/__opsdrill/pool-metrics');assert code==200 and metrics2['pid']==api.pid and metrics2['stage3']['generation']==generation
 assert get('http://127.0.0.1:8080/ready')[0]==200
 result={'status':'PASS','actor':'agent','run_id':rid,'restored_files':len(names),'app_lab_directory':str(lab),'app_backup_manifest_sha256':hashlib.sha256((backup/'manifest.json').read_bytes()).hexdigest(),'app_pid':api.pid,'stage3_pool_generation':generation,'baseline_http':200,'recovered_http':200,'baseline_amounts':[100,200],'recovered_amounts':[101,200],'scope':'restored selected application files and isolated synthetic PITR target; external lab dependencies and in-memory test database factories; not full production restore'}
finally:
 if listener is not None:listener.close()
 terminate(api,'API');terminate(proxy,'proxy')
 if attempted:
  try:
   target_sql("DROP USER IF EXISTS '"+account+"'@'localhost'")
   assert target_sql("SELECT COUNT(*) FROM mysql.user WHERE User='"+account+"' AND Host='localhost'")=='0'
   with (resultdir/'account-cleaned.json').open('x',encoding='utf-8') as f:
    json.dump({'run_id':rid,'account':account,'status':'ABSENT'},f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
   account_clean=True
  except Exception:
   print('test account cleanup unconfirmed; preserving M04 state',flush=True)
 if started and account_clean:
  q,items=action('reset',rid);clean=q.returncode==0
if not clean or result is None or not account_clean:raise RuntimeError('app restore, database restore or cleanup incomplete')
assert not os.path.lexists('/var/lib/opsdrill/cli/M04.json') and get('http://127.0.0.1:8080/ready')[0]==200
events=[json.loads(line) for line in Path('/var/lib/opsdrill/events.jsonl').read_text().splitlines()]
owned=[x for x in events if x.get('drill_id')=='M04' and x.get('run_id')==rid]
assert owned and all(x.get('actor')=='agent' for x in owned) and any(x.get('event')=='reset' and x.get('result')=='PASS' for x in owned)
result['cleanup']='PASS';result['business_ready_after']=200
fd=os.open(resultdir/'result.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
print('M04 restored app and isolated PITR target PASS; result',resultdir/'result.json',flush=True)
