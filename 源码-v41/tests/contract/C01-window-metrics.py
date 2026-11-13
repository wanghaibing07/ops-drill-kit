"""C01 bounded gateway and pool observation; not an RCA or global SLO proof."""
import hashlib,json,os,re,secrets,stat,subprocess,time,urllib.error,urllib.request
from pathlib import Path
CLI='/opt/ops-drill-kit/bin/opsdrill'
assert os.geteuid()==0
base=Path('/var')
for p in (base,*base.parents):
 s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
for part in ('backups','opsdrill','C01'):
 base=base/part
 try:base.mkdir(mode=0o700)
 except FileExistsError:pass
 s=base.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
assert not os.path.lexists('/var/lib/opsdrill/cli/C01.json')
outdir=base/('window-metrics-'+secrets.token_hex(8));outdir.mkdir(mode=0o700)
log=Path('/var/log/nginx/orderguard-timing.log');fd=os.open(log,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);st=os.fstat(fd);assert stat.S_ISREG(st.st_mode)
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
def service():
 q=subprocess.run(['/usr/bin/systemctl','show','orderguard-api','-p','ActiveState','-p','MainPID','-p','InvocationID'],capture_output=True,text=True,timeout=10,check=True,env=env)
 result=dict(x.split('=',1) for x in q.stdout.splitlines() if '=' in x)
 assert result['ActiveState']=='active' and result['MainPID'].isdigit() and int(result['MainPID'])>1 and re.fullmatch('[0-9a-f]{32}',result['InvocationID'])
 return result
def fetch(url,forwarded=False):
 req=urllib.request.Request(url,headers={'X-Forwarded-For':'192.0.2.1'} if forwarded else {})
 try:r=opener.open(req,timeout=5)
 except urllib.error.HTTPError as e:r=e
 with r:
  raw=r.read(65537);assert len(raw)<=65536
  try:obj=json.loads(raw)
  except (ValueError,UnicodeDecodeError):obj=None
  return r.status,r.headers.get('X-Request-ID',''),obj
def metrics():
 identity=service();status,_,body=fetch('http://127.0.0.1:8000/__opsdrill/pool-metrics');assert status==200 and body['pid']==int(identity['MainPID']) and body['scope']=='single-process-lab'
 assert service()==identity
 for name in ('legacy','stage3'):
  p=body[name];assert isinstance(p,dict) and not p['closed'] and p['capacity']==4 and p['quarantined']==0 and re.fullmatch('[0-9a-f]{32}',p['generation'])
  assert set(p['errors'])=={'closed','timeout','factory','ping','rollback','close','borrower'} and all(type(x) is int and x>=0 for x in p['errors'].values())
 assert abs(body['legacy']['monotonic_ns']-body['stage3']['monotonic_ns'])<1000000000
 return {'service':identity,'body':body}
def same_pools(first,last):
 assert first['service']==last['service'] and first['body']['pid']==last['body']['pid'] and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot
 for name in ('legacy','stage3'):
  a,b=first['body'][name],last['body'][name]
  assert a['generation']==b['generation'] and a['errors']==b['errors'] and a['monotonic_ns']<b['monotonic_ns']
def bounds():
 current=log.lstat();assert stat.S_ISREG(current.st_mode) and (current.st_dev,current.st_ino)==(st.st_dev,st.st_ino)
 size=os.fstat(fd).st_size;tail=os.pread(fd,min(size,256),max(0,size-256));return size,hashlib.sha256(tail).hexdigest()
def journal_cursor():
 q=subprocess.run(['journalctl','--unit=orderguard-api','--no-pager','--quiet','--lines=0','--show-cursor'],capture_output=True,text=True,timeout=10,check=True,env=env)
 matches=re.findall(r'^-- cursor: (.+)$',q.stdout,re.M);assert len(matches)==1 and len(matches[0])<2048
 return matches[0]
def save_evidence(name,data):
 assert '/' not in name and len(data)<=4000000
 target=outdir/name;out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(out,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 return hashlib.sha256(data).hexdigest()
def journal_errors(cursor,lower,upper,invocation,name):
 q=subprocess.run(['journalctl','--unit=orderguard-api','--no-pager','--quiet','--output=json','--after-cursor='+cursor],capture_output=True,timeout=10,check=True,env=env);assert len(q.stdout)<4000000
 entries=[];selected=[]
 for line in q.stdout.splitlines():
  try:r=json.loads(line);ts=int(r['__MONOTONIC_TIMESTAMP'])*1000
  except (ValueError,KeyError,TypeError):raise RuntimeError('invalid application journal')
  if lower<=ts<=upper:
   assert r.get('_BOOT_ID')==boot.replace('-','') and r.get('_SYSTEMD_INVOCATION_ID')==invocation
   entries.append(r);selected.append(line)
 text=[str(x.get('MESSAGE','')).lower() for x in entries]
 assert not any(any(key in x for key in ('pooltimeout','poolclosed','connection pool','database unavailable','traceback','suppressed ','dropped ')) for x in text)
 return len(entries),save_evidence(name+'-journal.jsonl',b'\n'.join(selected)+b'\n')
class PendingLog(RuntimeError):pass
def parse_log_window(raw,expected_ids):
 if not raw.endswith(b'\n'):raise PendingLog('log line incomplete')
 rows=[json.loads(x) for x in raw.splitlines()];counts={};seen={}
 for row in rows:
  assert isinstance(row,dict) and re.fullmatch('[0-9a-f]{32}',str(row.get('request_id',''))) and str(row.get('status','')).isdigit()
  code=int(row['status']);assert 100<=code<=599;counts[str(code)]=counts.get(str(code),0)+1
  if row['request_id'] in expected_ids:
   assert row['request_id'] not in seen
   seen[row['request_id']]=code
 if not all(key in seen for key in expected_ids):raise PendingLog('request missing')
 assert seen==expected_ids
 return counts,len(rows),len(seen)
def window(name,expected,with_pool):
 first=metrics() if with_pool else None;cursor=journal_cursor() if with_pool else None
 start,tail=bounds();wall_start=time.time_ns();mono_start=time.monotonic_ns();expected_ids={}
 for i in range(10):
  route='/orders/1001' if i%2==0 else '/api/v1/orders?merchant_id=88&page_size=1'
  code,request_id,body=fetch('http://127.0.0.1:8080'+route)
  assert code==expected and re.fullmatch('[0-9a-f]{32}',request_id) and request_id not in expected_ids
  if expected==200:
   assert (body.get('id')==1001 if i%2==0 else body.get('merchant_id')==88 and body.get('total')==25000 and len(body.get('items',[]))==1)
  expected_ids[request_id]=code;time.sleep(.1)
 deadline=time.monotonic()+5
 while True:
  end,_=bounds();assert end>=start and end-start<=1048576
  assert hashlib.sha256(os.pread(fd,min(start,256),max(0,start-256))).hexdigest()==tail
  raw=os.pread(fd,end-start,start)
  try:counts,row_count,seen_count=parse_log_window(raw,expected_ids);break
  except PendingLog:pass
  assert time.monotonic()<deadline;time.sleep(.1)
 wall_end=time.time_ns();mono_end=time.monotonic_ns();last=metrics() if with_pool else None
 if with_pool:same_pools(first,last)
 log_sha=save_evidence(name+'-timing.jsonl',raw)
 journal_count,journal_sha=journal_errors(cursor,mono_start,mono_end,first['service']['InvocationID'],name) if with_pool else (None,None)
 if with_pool:assert journal_count>=10
 return {'phase':name,'start_offset':start,'end_offset':end,'log_identity':[st.st_dev,st.st_ino],
         'wall_start_ns':wall_start,'wall_end_ns':wall_end,'monotonic_start_ns':mono_start,'monotonic_end_ns':mono_end,
         'requests':row_count,'status_counts':counts,'own_requests':seen_count,'pool_before':first,'pool_after':last,
         'timing_sha256':log_sha,'journal_entries':journal_count,'journal_sha256':journal_sha}
def action(name,rid=None):
 args=[CLI,name,'C01','--actor','agent']
 if rid:args+=['--expect-run-id',rid]
 q=subprocess.run(args,capture_output=True,text=True,timeout=120,env=env)
 try:r=json.loads(q.stdout)
 except ValueError:r={}
 return q.returncode,r
rid=None;clean=False
try:
 pre=window('baseline',200,False)
 rc,item=action('start');assert rc==0 and item.get('status')=='FAULT_CONFIRMED';rid=item['run_id'];assert re.fullmatch('[0-9a-f]{24}',rid)
 rc,item=action('check',rid);assert rc==1 and item.get('status')=='FAULT_PRESENT'
 fault=window('fault',502,False)
 note=subprocess.run([CLI,'note','C01','--kind','diagnosis','--actor','agent'],capture_output=True,text=True,timeout=30,env=env);assert note.returncode==0
 rc,item=action('resolve',rid);assert rc==0 and item.get('status')=='MITIGATED'
 rc,item=action('check',rid);assert rc==2 and item.get('status')=='RECOVERED_PARTIAL'
 code,_,_=fetch('http://127.0.0.1:8080/__opsdrill/pool-metrics');assert code==404
 recovered=window('recovered',200,True)
 b5=sum(v for k,v in pre['status_counts'].items() if int(k)>=500);r5=sum(v for k,v in recovered['status_counts'].items() if int(k)>=500)
 assert r5*pre['requests']<=b5*recovered['requests']
 rc,item=action('reset',rid);assert rc==0 and item.get('status')=='CLEANUP_PASS';clean=True
 status,_,ready=fetch('http://127.0.0.1:8080/ready');assert status==200 and ready['status']=='ready'
 result={'actor':'agent','run_id':rid,'status':'BOUNDED_AUTOMATED_OBSERVATION_PASS','scope':'three finite gateway windows; two instrumented pools during recovery only; not global zero errors or user RCA','baseline':pre,'fault':fault,'recovered':recovered,'ready_after':200,'cli_check':'RECOVERED_PARTIAL'}
 path=outdir/'result.json';out=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(out,'w') as f:json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
 digest=hashlib.sha256(path.read_bytes()).hexdigest()
 q=subprocess.run([CLI,'check','C01','--actor','agent','--expect-run-id',rid,'--evidence-dir',str(outdir),'--expected-sha256',digest],capture_output=True,text=True,timeout=120,env=env)
 try:assessment=json.loads(q.stdout)
 except ValueError:assessment={}
 assert q.returncode==0 and assessment.get('status')=='BOUNDED_OBSERVATION_PASS' and assessment.get('run_id')==rid and assessment.get('result_sha256')==digest
 print('C01 bounded metrics window and unified check PASS',rid,'evidence',str(path),flush=True)
finally:
 os.close(fd)
 if rid and not clean:
  try:rc,item=action('reset',rid);print('identity-bound C01 cleanup',rc,item.get('status'),flush=True)
  except Exception as exc:print('C01 cleanup requires inspection',rid,type(exc).__name__,flush=True)
