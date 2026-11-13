"""Run M02 baseline-v2 against isolated synthetic MySQL, never the main service."""
import argparse,contextlib,hashlib,importlib.util,io,json,os,pwd,secrets,shutil,stat,subprocess,sys,time
from pathlib import Path
from unittest.mock import patch
p=argparse.ArgumentParser();p.add_argument('--vm-uuid',required=True);p.add_argument('--apply',action='store_true');p.add_argument('--actor',choices=('agent',));a=p.parse_args();assert a.apply and a.actor=='agent' and os.geteuid()==0 and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==a.vm_uuid
ROOT=Path('/usr/local/libexec/opsdrill/m04-synthetic-v3');M02=Path('/usr/local/libexec/opsdrill/m02-baseline-v2/m02_deadlock.py')
pins={ROOT/'m04_controller.py':'46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9',ROOT/'continuation/mysql_live_identity.py':'c294cfa07973ef9342d4ca65147da14acbe6fa155ad29623edcda31fc48a42be',ROOT/'continuation/mysql_reset_gate.py':'eff466c8ad9dc5f7d2012a1b93aca33ffbb763d52ba8c39429f34ad7623178af',M02:'11e7e49054d660e521dc5aa0b0c2dab146bd6f9509634d5166e461d83a295b6c'}
for path,digest in pins.items():
 for d in (path.parent,*path.parent.parents):
  s=d.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:s=os.fstat(f.fileno());raw=f.read(1048577)
 assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and hashlib.sha256(raw).hexdigest()==digest
site=Path('/usr/lib/python3.11/site-packages');assert site.is_dir() and site.stat().st_uid==0
sys.path[:0]=[str(ROOT),str(ROOT/'continuation'),str(site)]
import pymysql
import m04_controller as ctl
import mysql_live_identity as live
spec=importlib.util.spec_from_file_location('m02_fixture_controller',M02);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
available=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
assert available>600*1024 and shutil.disk_usage('/var/tmp').free>2*1024**3
ctl.setup();rid=secrets.token_hex(8);directory=ctl.BASE/rid;directory.mkdir(mode=0o700);lock=ctl.locked(directory)
boot,now=ctl.boot_context();state={'version':1,'run_id':rid,'phase':'PREPARING','primary_uuid':live.SENTINEL,'uuids':{},'attempted':[],'boot_id':boot,'deadline_boottime':now+900,'business_phase':'TEST_ONLY','candidate_phase':'STARTING','actor':'agent'};ctl.save(directory,state)
print('isolated M02 fixture run',rid,flush=True);bound=False;clean=False
original_command=ctl.command
def command(r,label):
 args=original_command(r,label)
 return [('--performance-schema=ON' if x=='--performance-schema=OFF' and label=='source' else x) for x in args]
def phase(name):state['candidate_phase']=name;ctl.save(directory,state)
def sql(text):
 ctl.verify(rid,'source',state['primary_uuid'],state['uuids']['source']);socket=ctl.paths(rid,'source')[2]
 cmd=['/usr/bin/mysql','--no-defaults','--protocol=SOCKET','--socket='+str(socket),'--user=root','--batch','--raw','--skip-column-names','--skip-reconnect']
 q=subprocess.run(cmd,input=(text+'\n').encode(),capture_output=True,timeout=60,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C','MYSQL_HISTFILE':'/dev/null'})
 if q.returncode:raise RuntimeError('isolated SQL failed')
 ctl.verify(rid,'source',state['primary_uuid'],state['uuids']['source']);return q.stdout
try:
 with patch.object(ctl,'command',command):
  ctl.start(rid,directory,state);records=live.bind(rid,state,directory,ctl.verify);bound=True
  original_verify=ctl.verify
  def guarded(r,label,primary,expected=None):return live.guarded_verify(records,state,original_verify,r,label,primary,expected)
  with patch.object(ctl,'verify',guarded):
   phase('FIXTURE')
   assert sql('SELECT @@global.performance_schema,@@global.general_log,@@global.slow_query_log,@@global.log_bin,@@global.gtid_mode;').strip()==b'1\t0\t0\t1\tOFF'
   sql('CREATE DATABASE orderguard_stage3; CREATE TABLE orderguard_stage3.orders (id BIGINT UNSIGNED NOT NULL PRIMARY KEY, order_no VARCHAR(32) NOT NULL, order_status TINYINT UNSIGNED NOT NULL) ENGINE=InnoDB; INSERT INTO orderguard_stage3.orders VALUES (10086,\'fixture-10086\',2),(10087,\'fixture-10087\',3);')
   fixture=sql('SELECT id,order_no,order_status FROM orderguard_stage3.orders ORDER BY id;');assert fixture==b'10086\tfixture-10086\t2\n10087\tfixture-10087\t3\n'
   password=secrets.token_hex(24)
   sql("SET SESSION sql_log_bin=0; CREATE USER 'orderguard_m02_writer'@'localhost' IDENTIFIED BY '"+password+"'; GRANT SELECT (id,order_no,order_status), UPDATE (order_status) ON orderguard_stage3.orders TO 'orderguard_m02_writer'@'localhost'; SET SESSION sql_log_bin=1;")
   fixture_dir=directory/'m02-fixture';fixture_dir.mkdir(mode=0o700);conf=fixture_dir/'config';conf.mkdir(mode=0o700);status=fixture_dir/'state';status.mkdir(mode=0o700)
   evidence=fixture_dir/'evidence';evidence.mkdir(mode=0o755);u=pwd.getpwnam('devops');os.chown(evidence,u.pw_uid,u.pw_gid);os.chmod(evidence,0o755)
   socket=str(ctl.paths(rid,'source')[2]);admin=conf/'admin.cnf';writer=conf/'writer.cnf'
   for file,content in ((admin,'[client]\nuser=root\nsocket='+socket+'\n'),(writer,'[client]\nuser=orderguard_m02_writer\npassword='+password+'\nsocket='+socket+'\n')):
    fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:f.write(content);f.flush();os.fsync(f.fileno())
   del password
   m.ADMIN_CNF=admin;m.WRITER_CNF=writer;m.STATE_DIR=status;m.STATE_FILE=status/'state.json';m.LOCK_FILE=fixture_dir/'lock';m.EVIDENCE_DIR=evidence
   original_connect=m.connect_mysql
   def checked_connect(option_file,autocommit):
    assert option_file in (admin,writer);ctl.verify(rid,'source',state['primary_uuid'],state['uuids']['source'])
    connection=original_connect(option_file,autocommit)
    with connection.cursor() as cur:cur.execute('SELECT @@server_uuid');actual=cur.fetchone()[0]
    if actual.lower()!=state['uuids']['source'].lower():connection.close();raise RuntimeError('connection identity mismatch')
    ctl.verify(rid,'source',state['primary_uuid'],state['uuids']['source']);return connection
   m.connect_mysql=checked_connect
   phase('M02_INJECT');owned=secrets.token_hex(12)
   with contextlib.redirect_stdout(io.StringIO()):m.inject(owned_run_id=owned);m.check();m.reset();m.reset()
   mstate=m.read_state();assert mstate['phase']=='reset-completed' and mstate['owner_run_id']==owned
   assert sql('SELECT id,order_no,order_status FROM orderguard_stage3.orders ORDER BY id;')==fixture
   phase('DROP_FIXTURE_ACCOUNT');sql("SET SESSION sql_log_bin=0; DROP USER 'orderguard_m02_writer'@'localhost'; SET SESSION sql_log_bin=1;")
   assert sql("SELECT COUNT(*) FROM mysql.user WHERE User='orderguard_m02_writer' AND Host='localhost';").strip()==b'0'
   for file in (admin,writer):
    st=file.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1;file.unlink()
   phase('STOPPING');live.reset(rid,state,directory);clean=True;phase('M02_FIXTURE_VERIFIED_STOPPED')
   result={'actor':'agent','run_id':rid,'m02_owner_run_id':owned,'status':'PASS','scope':'baseline-v2 isolated socket-only synthetic fixture; controller inject/check/reset twice; not production or normal CLI','fixture_sha256':hashlib.sha256(fixture).hexdigest(),'m02_evidence_sha256':mstate['evidence_sha256'],'controller_sha256':pins[M02],'source_uuid':state['uuids']['source'],'target_uuid':state['uuids']['target'],'credentials_retained':False}
   fd=os.open(directory/'m02-fixture-result.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'w') as f:json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
   print('isolated M02 fixture passed',rid,flush=True)
except BaseException as exc:
 state['candidate_failed_phase']=state.get('candidate_phase');state['candidate_error_type']=type(exc).__name__;phase('NEEDS_INSPECTION')
 print('M02 fixture unconfirmed; retained',rid,type(exc).__name__,flush=True);raise
finally:
 os.close(lock)
 if bound and not clean:print('inspect identity-bound temporary instances',rid,flush=True)
