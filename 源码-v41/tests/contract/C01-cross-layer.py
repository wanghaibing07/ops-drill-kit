"""Small, bounded C01 evidence experiment; executed as auto in the lab."""
import hashlib,importlib.machinery,importlib.util,json,os,re,secrets,stat,subprocess,sys,time
import urllib.error,urllib.request
from pathlib import Path

project=Path('/opt/ops-drill-kit');cli=str(project/'bin/opsdrill')
base=Path('/var/backups/opsdrill/Baseline/verify-candidate-20261113-v3')
for directory in (base,*base.parents):
 st=directory.lstat()
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('baseline validator directory unsafe')
for name,digest in {'verify':'05aa0c41f273bafb7c6c92937499e4b6a81599a9a9bee586e5c002e0db7a42d4',
                    'common.py':'de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4'}.items():
 p=base/name;st=p.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022 or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:
  raise RuntimeError('baseline validator mismatch')
sys.path.insert(0,str(base));loader=importlib.machinery.SourceFileLoader('c01_baseline_verify',str(base/'verify'))
spec=importlib.util.spec_from_loader(loader.name,loader);verify=importlib.util.module_from_spec(spec);loader.exec_module(verify)
verify.check_admin_options()
stage=Path('/var/backups/opsdrill/C01')/('cross-layer-'+secrets.token_hex(8));stage.mkdir(mode=0o700)
log=Path('/var/log/nginx/orderguard-timing.log')
fd=os.open(log,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);info=os.fstat(fd)
if not stat.S_ISREG(info.st_mode):raise RuntimeError('timing log is not regular')
os.lseek(fd,0,os.SEEK_END)
observations=[];rid=None;clean=False
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))

def service(name):
 p=subprocess.run(['/usr/bin/systemctl','show',name,'--property=ActiveState','--value'],capture_output=True,text=True,timeout=10,check=True)
 return p.stdout.strip()
def mysql_snapshot():
 verify.check_admin_options()
 sql=b'SELECT (SELECT COUNT(*) FROM orderguard.orders),(SELECT COUNT(*) FROM performance_schema.data_lock_waits),(SELECT COUNT(*) FROM performance_schema.threads WHERE TYPE="FOREGROUND");\n'
 rc,out=verify.c.command(['mysql','--defaults-file=/etc/opsdrill/mysql-admin.cnf','--host=localhost',
   '--protocol=SOCKET','--socket=/var/lib/mysql/mysql.sock','--batch','--raw','--skip-column-names','--skip-reconnect'],sql,timeout=15)
 vals=out.strip().split(b'\t')
 if rc!=0 or len(vals)!=3 or any(not x.isdigit() for x in vals):raise RuntimeError('database observation unavailable')
 count,waits,connections=map(int,vals)
 if count!=5:raise RuntimeError('legacy data differs')
 return {'legacy_orders':count,'lock_waits_observed':waits,'foreground_threads_observed':connections}
def request():
 try:
  response=opener.open('http://127.0.0.1:8080/orders/1001',timeout=5)
 except urllib.error.HTTPError as e:response=e
 with response:
  code=response.status;request_id=response.headers.get('X-Request-ID','')
 if not re.fullmatch('[0-9a-f]{32}',request_id):raise RuntimeError('request ID missing')
 return {'status':code,'request_id':request_id}
def sample(stage_name,expected_code,expected_app):
 snap={'phase':stage_name,'nginx':service('nginx'),'api':service('orderguard-api'),
       'mysql':service('mysqld'),'database':mysql_snapshot(),'requests':[request() for _ in range(3)]}
 if snap['nginx']!='active' or snap['mysql']!='active' or snap['api']!=expected_app or any(x['status']!=expected_code for x in snap['requests']):
  raise RuntimeError('cross-layer observation mismatch')
 observations.append(snap)
 print(stage_name,'gateway',expected_code,'api',expected_app,'db reachable',flush=True)
def action(name,run_id=None):
 args=[cli,name,'C01']
 if run_id:args+=['--expect-run-id',run_id]
 p=subprocess.run(args,capture_output=True,text=True,timeout=120)
 try:result=json.loads(p.stdout)
 except ValueError:result={}
 return p,result

try:
 sample('baseline',200,'active')
 p,item=action('start')
 if p.returncode!=0 or item.get('status')!='FAULT_CONFIRMED':raise RuntimeError('start unconfirmed; preserve state')
 rid=item.get('run_id')
 if not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{24}',rid):raise RuntimeError('run ID invalid')
 p,item=action('check',rid)
 if p.returncode!=1 or item.get('status')!='FAULT_PRESENT':raise RuntimeError('fault check unconfirmed')
 sample('fault',502,'inactive')
 note=subprocess.run([cli,'note','C01','--kind','diagnosis'],capture_output=True,text=True,timeout=30)
 if note.returncode:raise RuntimeError('diagnosis marker failed')
 p,item=action('resolve',rid)
 if p.returncode or item.get('status')!='MITIGATED':raise RuntimeError('mitigation unconfirmed')
 p,item=action('check',rid)
 if p.returncode!=2 or item.get('status')!='RECOVERED_PARTIAL':raise RuntimeError('partial check unconfirmed')
 sample('recovered',200,'active')
 p,item=action('reset',rid)
 if p.returncode or item.get('status')!='CLEANUP_PASS':raise RuntimeError('reset unconfirmed')
 clean=True
 with opener.open('http://127.0.0.1:8080/ready',timeout=5) as response:
  if response.status!=200:raise RuntimeError('readiness unconfirmed')
 expected={r['request_id']:r['status'] for phase in observations for r in phase['requests']}
 if len(expected)!=9:raise RuntimeError('request IDs repeated')
 deadline=time.monotonic()+5;log_rows={};buffer=b''
 while time.monotonic()<deadline and len(log_rows)<len(expected):
  st=log.lstat()
  if not stat.S_ISREG(st.st_mode) or (st.st_dev,st.st_ino)!=(info.st_dev,info.st_ino):raise RuntimeError('timing log rotated')
  buffer+=os.read(fd,65536)
  if len(buffer)>262144:raise RuntimeError('timing log window too large')
  parts=buffer.split(b'\n');buffer=parts.pop()
  for line in parts:
   try:row=json.loads(line)
   except (ValueError,UnicodeDecodeError):continue
   if isinstance(row,dict) and row.get('request_id') in expected:
    request_id=row['request_id'];code=row.get('status')
    if str(code)!=str(expected[request_id]) or request_id in log_rows:raise RuntimeError('timing log mismatch')
    log_rows[request_id]=int(code)
  if len(log_rows)<len(expected):time.sleep(.1)
 if len(log_rows)!=9:raise RuntimeError('timing logs incomplete')
 report=subprocess.run(['/usr/bin/python3','-B',str(project/'scripts/report.py')],capture_output=True,text=True,timeout=30,check=True)
 attempts=[x for x in json.loads(report.stdout)['attempts'] if x.get('run_id')==rid]
 if len(attempts)!=1 or attempts[0].get('status')!='PARTIAL' or attempts[0].get('mttr_proxy_seconds') is not None:
  raise RuntimeError('report status mismatch')
 result={'run_id':rid,'status':'CROSS_LAYER_SAMPLE_PASS','observations':observations,
         'matched_timing_requests':len(log_rows),'report_status':'PARTIAL',
         'scope':'three requests per phase; not a global error-rate baseline, full pool audit, or user exercise'}
 path=stage/'result.json'
 with path.open('x',encoding='utf8') as f:json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 print('C01 cross-layer sample verified:',rid,stage,flush=True)
finally:
 os.close(fd)
 if rid and not clean:
  print('Attempt identity-bound reset:',rid,flush=True)
  try:action('reset',rid)
  except Exception as exc:print('Reset unconfirmed:',type(exc).__name__,flush=True)
