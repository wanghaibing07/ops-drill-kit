import argparse,base64,hashlib,importlib.util,json,os,pwd,secrets,socket,stat,subprocess,time,urllib.error,urllib.request,zlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--vm-uuid',required=True);p.add_argument('--source-root',required=True);a=p.parse_args()
assert os.geteuid()==0 and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==a.vm_uuid
root=Path(a.source_root);assert root.is_absolute();cli=root/'bin/opsdrill'
pins={'app/main.py':'c66ec5b96019ed02293d676f2d66aeada60ab51765fbe2a2f2bab0dca7b77126','app/stage3_api.py':'1b1de2012ad6402bcd8e54edc3ac71014663153487c017367833aa83a9f07334','app/n03_slow.py':'2efb68db6aad54239b2c0fd42b85fae9947b87ff7ac20c712b41afeef9cdae99','app/bounded_pool.py':'d03cfece4535af585288a64e1d027d3488b1cb447bc191033494b04cf45b2747','scripts/opsdrill_cli.py':'8edac648dc7ad06dd9b23029723f3bb0513d18539f75ddc8803ec57c69e04722','bin/opsdrill':'5976790b5f19433e51179c902518d873e8cba4bcb77d7cc8fe9abf2077f70e43'}
for d in (root/'app',root/'scripts',root/'bin',root,*root.parents):
 s=d.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
contents={}
for name,digest in pins.items():
 fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:s=os.fstat(f.fileno());data=f.read(1048577)
 assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022 and hashlib.sha256(data).hexdigest()==digest
 contents[name]=data
u=pwd.getpwnam('devops');env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
assert not os.path.lexists('/var/lib/opsdrill/cli/M03.json')
mem={x.split(':',1)[0]:int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')};assert mem.get('MemAvailable',0)>=512*1024
test=subprocess.run(['/opt/ops-drill-kit/.venv/bin/python','-I','-B','-c','import fastapi,uvicorn,pymysql'],user=u.pw_uid,group=u.pw_gid,extra_groups=[],env=env,capture_output=True,timeout=15);assert test.returncode==0
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(url):
 try:r=opener.open(url,timeout=6)
 except urllib.error.HTTPError as e:r=e
 with r:
  body=r.read(65537);assert len(body)<=65536
  try:data=json.loads(body)
  except (ValueError,UnicodeError):data={}
  return r.status,data
assert get('http://127.0.0.1:8080/ready')[0]==200
base=Path('/var/backups/opsdrill')
for d in (base,*base.parents):
 st=d.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
backup=base/'M03'
try:backup.mkdir(mode=0o700)
except FileExistsError:pass
st=backup.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
resultdir=backup/('app-readiness-'+secrets.token_hex(8));resultdir.mkdir(mode=0o700)
stage=Path('/var/tmp')/('opsdrill-m03-api-'+secrets.token_hex(8));stage.mkdir(mode=0o750);os.chown(stage,0,u.pw_gid);os.chmod(stage,0o750)
appdir=stage/'app';appdir.mkdir(mode=0o750);os.chown(appdir,0,u.pw_gid);os.chmod(appdir,0o750)
helpers=Path(__file__).absolute().parent
for d in (helpers,*helpers.parents):
 st=d.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
helper_pins={'m03-api-proxy.py': 'fa0d697bdcb13235fb12c079ccddd0d90203bc2f5295fcc7c3392cc84d8a217a', 'm03-api-probe-server.py': '55c2a89920fc2c6f380de060195eb486e5f0e07c5bae4299a6301c1083ff113a'}
helper_data=[]
for name,digest in helper_pins.items():
 fd=os.open(helpers/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:st=os.fstat(f.fileno());data=f.read(1048577)
 assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022 and hashlib.sha256(data).hexdigest()==digest
 helper_data.append(data)
def write_file(path,data,mode):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:f.write(data);os.fchown(f.fileno(),0,u.pw_gid);os.fchmod(f.fileno(),mode);f.flush();os.fsync(f.fileno())
for name,data in contents.items():
 if name.startswith('app/'):write_file(stage/name,data,0o640)
for name,data in zip(('proxy.py','server.py'),helper_data):write_file(stage/name,data,0o640)
spec=importlib.util.spec_from_file_location('reviewed_cli',root/'scripts/opsdrill_cli.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
rid=None;started=False;reset_done=False;reset_attempted=False;proxy=None;api=None;listener=None;result=None
def action(name,rid=None):
 args=[str(cli),name,'M03','--actor','agent']
 if rid:args+=['--expect-run-id',rid]
 q=subprocess.run(args,capture_output=True,text=True,timeout=780 if name=='start' else 420,env=env)
 parsed=[]
 for line in q.stdout.splitlines():
  try:parsed.append(json.loads(line))
  except ValueError:pass
 print('M03',name,'exit',q.returncode,flush=True)
 return q,parsed
def terminate(proc,name):
 if proc is None:return
 if proc.poll() is None:
  proc.terminate()
  try:proc.wait(timeout=15)
  except subprocess.TimeoutExpired:raise RuntimeError(name+' did not stop; preserve state')
try:
 q,items=action('start');state_path=Path('/var/lib/opsdrill/cli/M03.json')
 if q.returncode or not state_path.exists():raise RuntimeError('M03 start unconfirmed; preserve state')
 x=json.loads(state_path.read_text());rid=x.get('run_id');attempt=x.get('attempt_id')
 assert x.get('drill_id')=='M03' and x.get('phase')=='ACTIVE' and isinstance(rid,str) and len(rid)==24
 started=True
 q,items=action('check',rid);assert q.returncode==1 and items and items[-1].get('mysql_error')==1040
 v.m03_command('check',rid)
 module_path=Path('/usr/local/libexec/opsdrill/m03-mysql-v1/mysql_lifecycle.py')
 spec=importlib.util.spec_from_file_location('verified_m03_lifecycle',module_path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 directory=m.run_directory(rid);owner=m.owner_for(directory,rid);m.identity(directory,owner)
 ctl,probe=m.load_dependencies();dbid=owner['db_id'];dbdir=ctl.BASE/dbid;dbstate=ctl.load(dbdir,dbid);m.state_belongs(dbstate,owner);probe.target(ctl,dbid,dbstate)
 target=ctl.paths(dbid,'target')[2];s=target.lstat();assert stat.S_ISSOCK(s.st_mode)
 proxy_path=stage/'proxy.sock'
 proxy=subprocess.Popen(['/usr/bin/python3','-I','-B',str(stage/'proxy.py'),str(proxy_path),str(target),str(s.st_dev),str(s.st_ino),str(u.pw_uid),str(u.pw_gid)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,start_new_session=True)
 deadline=time.monotonic()+10
 while not proxy_path.exists():
  assert proxy.poll() is None and time.monotonic()<deadline;time.sleep(.1)
 s=proxy_path.lstat();assert stat.S_ISSOCK(s.st_mode) and s.st_uid==0 and s.st_gid==u.pw_gid and stat.S_IMODE(s.st_mode)==0o660
 listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);listener.bind(('127.0.0.1',0));listener.listen(16);port=listener.getsockname()[1]
 testenv=dict(env,M03_APP_SOURCE=str(stage),M03_PROXY_SOCKET=str(proxy_path),M03_PUBLIC_USER='m03_'+dbid,M03_PUBLIC_MARKER=probe.MARKER,M03_HTTP_FD=str(listener.fileno()))
 api=subprocess.Popen(['/opt/ops-drill-kit/.venv/bin/python','-I','-B',str(stage/'server.py')],user=u.pw_uid,group=u.pw_gid,extra_groups=[],pass_fds=(listener.fileno(),),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=testenv,start_new_session=True)
 listener.close();listener=None;url='http://127.0.0.1:'+str(port)
 deadline=time.monotonic()+15
 while True:
  assert api.poll() is None and proxy.poll() is None and time.monotonic()<deadline
  try:
   code,body=get(url+'/health')
   if code==200 and body.get('status')=='ok':break
  except (OSError,urllib.error.URLError):time.sleep(.1)
 code,before=get(url+'/__opsdrill/pool-metrics');assert code==200 and before['pid']==api.pid
 fault,_=get(url+'/ready');assert fault==503
 code,after_fault=get(url+'/__opsdrill/pool-metrics');assert code==200 and after_fault['pid']==api.pid
 assert after_fault['legacy']['generation']==before['legacy']['generation'] and after_fault['legacy']['errors']['factory']==before['legacy']['errors']['factory']+1
 q,items=action('resolve',rid);assert q.returncode==0
 q,items=action('check',rid);assert q.returncode==0 and items[-1].get('status')=='RECOVERED'
 recovered,body=get(url+'/ready');assert recovered==200 and body.get('status')=='ready'
 code,after_recovery=get(url+'/__opsdrill/pool-metrics');assert code==200 and after_recovery['pid']==api.pid and after_recovery['legacy']['generation']==before['legacy']['generation']
 assert after_recovery['legacy']['errors']['factory']==after_fault['legacy']['errors']['factory']
 assert get('http://127.0.0.1:8080/ready')[0]==200
 result={'status':'PASS','actor':'agent','run_id':rid,'attempt_id':attempt,'mysql_error':1040,'isolated_api_fault_http':fault,'isolated_api_recovered_http':recovered,'api_pid':api.pid,'pool_generation':before['legacy']['generation'],'pool_factory_error_delta_fault':1,'pool_factory_error_delta_recovery':0,'scope':'actual FastAPI readiness handler with in-memory DB factory adapter and peer-restricted relay to this isolated synthetic MySQL; production API unchanged'}
finally:
 if listener is not None:listener.close()
 terminate(api,'API');terminate(proxy,'proxy')
 if started and not reset_attempted:
  reset_attempted=True;q,items=action('reset',rid);reset_done=q.returncode==0
if not reset_done or result is None:raise RuntimeError('M03 API test or identity-bound cleanup incomplete')
assert not os.path.lexists('/var/lib/opsdrill/cli/M03.json') and get('http://127.0.0.1:8080/ready')[0]==200
events=[json.loads(line) for line in Path('/var/lib/opsdrill/events.jsonl').read_text().splitlines()]
owned=[x for x in events if x.get('drill_id')=='M03' and x.get('attempt_id')==attempt]
assert owned and all(x.get('actor')=='agent' for x in owned) and any(x.get('event')=='reset' and x.get('result')=='PASS' for x in owned)
result['cleanup']='PASS';result['business_ready_after']=200
fd=os.open(resultdir/'result.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
print('M03 isolated API readiness integration PASS; result',resultdir/'result.json',flush=True)
