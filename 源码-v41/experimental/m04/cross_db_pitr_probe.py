"""Isolated two-schema one-transaction PITR probe; no production writes.

This probes synthetic fixtures only. Root is used for isolated restore/replay;
it is not a production backup account or an integrated CLI contract.
"""
import base64,hashlib,json,os,re,secrets,stat,struct,subprocess,sys,time,zlib
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path('/usr/local/libexec/opsdrill/m04-synthetic-v3')
MANIFEST={'m04_controller.py':'46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9','m04_business.py':'17c401b9144efc3d2e0b7b5f72ca20da04220a512b4514a564405b8a35a872ef','m04_replay_account.py':'15a112d035563f1a2e8088c4a7c7f8ffc6ee5e7425d3f9ba68a8dfcb1d52234d','vm_replay_probe.py':'569af2c7ef921b09d005581d860f64681e78735f019e1d2698672fffbb10da97','pitr_audit.py':'3b6d5fa1ee4c5227d3ae33a825b92bac8c96d6b054a80bfda2537ea03cb6c51e','sealed_replay.py':'5e8487ab4b6ab7acc6b3dc961456159c9a1ce30a0cce5d784b9d43e503597e7f','stream_envelope.py':'95b9307b280e568df1332657e67b525198b4159f3e498c3a5ae3a14128a9c520','continuation/mysql_lifecycle_candidate.py':'9b025309dfcb3ab5bc1b3db975fceb2d8cab3672ed912f44c03176fa7879e746','continuation/mysql_synthetic_drill.py':'1b7f6df409438ba7653bfd0b1b94c7ab41b0e93531d1a4b0488cd4bd5d586cb0','continuation/mysql_live_identity.py':'c294cfa07973ef9342d4ca65147da14acbe6fa155ad29623edcda31fc48a42be','continuation/mysql_reset_gate.py':'eff466c8ad9dc5f7d2012a1b93aca33ffbb763d52ba8c39429f34ad7623178af','continuation/mysql_backup_gate.py':'3761d0323109a48795f8e222ae4fea4d104bdd56202a362ee0567946fff1b8bb','continuation/mysql_binlog_gate.py':'f35dc69743710157359e1cbb55f4f4b6997b52c687c8f0185843a7a3d97ea917','continuation/mysql_fixture_gate.py':'5729222c7028879e36bee1cbfd50d7124cefb0d5459ef290906bce73bc286e15'}
def need(v,msg):
    if not v:raise ValueError(msg)
for p in (ROOT/'continuation',ROOT,*ROOT.parents):
    s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'unsafe runtime path')
need(set(os.listdir(ROOT))=={n for n in MANIFEST if '/' not in n}|{'continuation'},'runtime root inventory')
need(set(os.listdir(ROOT/'continuation'))=={n.split('/')[1] for n in MANIFEST if '/' in n},'runtime child inventory')
for name,digest in MANIFEST.items():
    fd=os.open(ROOT/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:s=os.fstat(f.fileno());raw=f.read(1048577)
    need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022 and hashlib.sha256(raw).hexdigest()==digest,'runtime mismatch')
sys.path[:0]=[str(ROOT),str(ROOT/'continuation')]
import m04_controller as ctl
import mysql_live_identity as live
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C','MYSQL_HISTFILE':'/dev/null'}
if sys.argv[1:] != ['--apply','--actor','agent']:
    raise SystemExit('Explicit --apply --actor agent required; run a verified root-protected copy')
ctl.setup();rid=secrets.token_hex(8);directory=ctl.BASE/rid;directory.mkdir(mode=0o700);lock=ctl.locked(directory)
boot,now=ctl.boot_context();state={'version':1,'run_id':rid,'phase':'PREPARING','primary_uuid':live.SENTINEL,'uuids':{},'attempted':[],'boot_id':boot,'deadline_boottime':now+900,'business_phase':'TEST_ONLY','candidate_phase':'STARTING','actor':'agent'}
ctl.save(directory,state);print('isolated cross-db run',rid,flush=True)
bound=False;clean=False
def phase(value):state['candidate_phase']=value;ctl.save(directory,state)
def call(args,data=None,timeout=90):
    p=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=timeout)
    need(p.returncode==0 and len(p.stdout)<8*1024*1024,'subprocess failed '+Path(args[0]).name)
    return p.stdout
def query(label,sql):
    ctl.verify(rid,label,state['primary_uuid'],state['uuids'][label]);sock=ctl.paths(rid,label)[2]
    cmd=['/usr/bin/mysql','--no-defaults','--host=localhost','--protocol=SOCKET','--socket='+str(sock),'--user=root','--batch','--raw','--skip-column-names','--skip-reconnect']
    result=call(cmd,(sql+'\n').encode('ascii'));ctl.verify(rid,label,state['primary_uuid'],state['uuids'][label]);return result
def position():
    fields=query('source','SHOW BINARY LOG STATUS;').decode('ascii').strip().split('\t')
    need(len(fields)>=2 and re.fullmatch(r'pitr-bin\.\d{6}',fields[0]) and fields[1].isdigit(),'bad position')
    return [fields[0],int(fields[1])]
def snapshot(label):
    values={}
    for db in ('cross_a','cross_b'):
        values[db]={'rows':hashlib.sha256(query(label,'SELECT id,value FROM '+db+'.items ORDER BY id;')).hexdigest(),
                    'schema':hashlib.sha256(query(label,'SHOW CREATE TABLE '+db+'.items;')).hexdigest()}
    return values
def events(raw):
    need(raw[:4]==b'\xfebin','magic');out=[];pos=4
    while pos<len(raw):
        need(pos+19<=len(raw),'short header');_,kind,server,size,nextpos,_=struct.unpack('<IBIIIH',raw[pos:pos+19])
        need(size>=23 and pos+size<=len(raw) and nextpos==pos+size,'bad event bounds')
        ev=raw[pos:nextpos];need(zlib.crc32(ev[:-4])&0xffffffff==int.from_bytes(ev[-4:],'little'),'bad crc')
        out.append((pos,nextpos,kind,server,ev));pos=nextpos
    need(pos==len(raw),'bad length');return out
def map_table(body):
    need(len(body)>=10,'short table map');tid=int.from_bytes(body[:6],'little');n=body[8];j=9
    need(j+n+2<=len(body) and body[j+n]==0,'schema map');db=body[j:j+n].decode('ascii');j+=n+1
    n=body[j];j+=1;need(j+n+1<=len(body) and body[j+n]==0,'table map');table=body[j:j+n].decode('ascii');j+=n+1
    need(db in ('cross_a','cross_b') and table=='items' and tid>0,'unexpected table')
    need(body[j:j+4]==b'\x02\x03\x03\x00' and body[j+4:j+5]==b'\x00','unexpected table contract')
    return tid,db
def update_row(body,tid):
    need(int.from_bytes(body[:6],'little')==tid and len(body)>=10,'row table mismatch')
    extra=int.from_bytes(body[8:10],'little');i=8+extra
    need(extra>=2 and body[i:i+3]==b'\x02\x03\x03','partial update');i+=3
    need(len(body)==i+18 and body[i]==0 and body[i+9]==0,'update cardinality')
    old=struct.unpack('<II',body[i+1:i+9]);new=struct.unpack('<II',body[i+10:i+18])
    need(old==(1,100) and new==(1,101),'unexpected row update')
def delete_row(body,tid):
    need(int.from_bytes(body[:6],'little')==tid and len(body)>=10,'delete table mismatch')
    extra=int.from_bytes(body[8:10],'little');i=8+extra
    need(extra>=2 and body[i:i+2]==b'\x02\x03','partial delete');i+=2
    need(len(body)==i+9 and body[i]==0 and struct.unpack('<II',body[i+1:i+9])==(2,200),'unexpected delete row')
try:
    ctl.start(rid,directory,state);records=live.bind(rid,state,directory,ctl.verify);bound=True
    original=ctl.verify
    def guarded(r,label,primary,expected=None):return live.guarded_verify(records,state,original,r,label,primary,expected)
    with patch.object(ctl,'verify',guarded):
        phase('FIXTURE'); identities={}
        for label in ('source','target'):
            identities[label]=query(label,'SELECT @@server_uuid,@@server_id,@@global.gtid_mode,@@session.sql_log_bin,@@global.log_bin,@@global.skip_networking;').decode().strip().split('\t')
        need(identities['source'][0]!=identities['target'][0] and identities['source'][1]!=identities['target'][1] and identities['source'][2:] == ['OFF','1','1','1'] and identities['target'][2:] == ['OFF','1','0','1'],'unexpected instance settings')
        for db in ('cross_a','cross_b'):
            query('source','CREATE DATABASE '+db+'; CREATE TABLE '+db+'.items (id INT UNSIGNED NOT NULL PRIMARY KEY, value INT UNSIGNED NOT NULL) ENGINE=InnoDB; INSERT INTO '+db+'.items VALUES (1,100),(2,200);')
        query('source','FLUSH BINARY LOGS;');start=position()
        sock=ctl.paths(rid,'source')[2]
        dump=call(['/usr/bin/mysqldump','--no-defaults','--protocol=SOCKET','--socket='+str(sock),'--user=root','--single-transaction','--source-data=2','--set-gtid-purged=OFF','--no-tablespaces','--databases','cross_a','cross_b'])
        need(position()==start,'backup changed coordinate');baseline=snapshot('source')
        dump_path=directory/'synthetic-backup.sql';fd=os.open(dump_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(dump);f.flush();os.fsync(f.fileno())
        state['backup_sha256']=hashlib.sha256(dump).hexdigest();state['identities']=identities;ctl.save(directory,state)
        target_sock=ctl.paths(rid,'target')[2]
        call(['/usr/bin/mysql','--no-defaults','--protocol=SOCKET','--socket='+str(target_sock),'--user=root','--skip-reconnect'],dump)
        need(snapshot('target')==baseline,'backup restore mismatch')
        phase('INJECTING')
        query('source','START TRANSACTION; UPDATE cross_a.items SET value=101 WHERE id=1; UPDATE cross_b.items SET value=101 WHERE id=1; COMMIT;')
        stop=position();t1=snapshot('source');need(t1!=baseline,'updates missing')
        state.update(backup_start=start,replay_stop=stop,baseline_sha=baseline,t1_sha=t1);ctl.save(directory,state)
        query('source','DELETE FROM cross_b.items WHERE id=2;');end=position();fault=snapshot('source')
        need(fault['cross_a']==t1['cross_a'] and fault['cross_b']['rows']!=t1['cross_b']['rows'],'delete not observed')
        need(start[0]==stop[0]==end[0] and start[1]<stop[1]<end[1],'boundary mismatch')
        query('source','FLUSH BINARY LOGS;');need(position()[0]!=start[0],'rotation mismatch')
        path=ctl.paths(rid,'source')[1]/start[0];fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as f:s=os.fstat(f.fileno());raw=f.read(8*1024*1024+1)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and len(raw)<=8*1024*1024,'bad binlog')
        import importlib.util
        auditor_path=Path('/var/backups/opsdrill/M04/cross-db-auditor-0af9f92c742ca0ea/cross_db_audit.py')
        for d in (auditor_path.parent,*auditor_path.parent.parents):
            st=d.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'unsafe auditor directory')
        fd=os.open(auditor_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'rb') as f:st=os.fstat(f.fileno());source=f.read(1048577)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022 and hashlib.sha256(source).hexdigest()=='0af9f92c742ca0ead61149997785aa733077e7089644eb0c7916aaaeb92c8787','auditor mismatch')
        auditor=type(sys)('cross_db_audit');exec(compile(source,str(auditor_path),'exec'),auditor.__dict__)
        checked=auditor.audit(raw,start[1],stop[1],end[1],hashlib.sha256(raw).hexdigest())
        replay=("SET @@SESSION.PSEUDO_SLAVE_MODE=1;\nBINLOG '"+base64.b64encode(checked['format_event']).decode()+"';\nSTART TRANSACTION;\nBINLOG '"+base64.b64encode(checked['row_events']).decode()+"';\nCOMMIT;\nSET @@SESSION.PSEUDO_SLAVE_MODE=0;\n").encode('ascii')
        state.update(fault_end=end,binlog_sha256=hashlib.sha256(raw).hexdigest(),replay_sha256=hashlib.sha256(replay).hexdigest(),auditor_sha256='0af9f92c742ca0ead61149997785aa733077e7089644eb0c7916aaaeb92c8787');phase('REPLAYING')
        ctl.verify(rid,'target',state['primary_uuid'],state['uuids']['target'])
        call(['/usr/bin/mysql','--no-defaults','--protocol=SOCKET','--socket='+str(target_sock),'--user=root','--skip-reconnect'],replay)
        need(snapshot('target')==t1,'PITR differs from before-delete state')
        need(query('target','SELECT id,value FROM cross_a.items ORDER BY id;')==b'1\t101\n2\t200\n' and query('target','SELECT id,value FROM cross_b.items ORDER BY id;')==b'1\t101\n2\t200\n','target rows mismatch')
        phase('STOPPING');live.reset(rid,state,directory);clean=True;phase('CROSS_DB_VERIFIED_STOPPED')
        result={'actor':'agent','run_id':rid,'status':'PASS','scope':'two synthetic databases, same transaction, one binlog; isolated socket-only, GTID OFF, root restore/replay; not integrated CLI or production snapshot','start':start,'stop':stop,'end':end,'identities':identities,'baseline':baseline,'before_delete':t1,'restored':t1,'backup_sha256':state['backup_sha256'],'binlog_sha256':state['binlog_sha256'],'replay_sha256':state['replay_sha256'],'auditor_sha256':state['auditor_sha256']}
        p=directory/'cross-db-result.json';fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
        print('cross-db PITR verified',rid,flush=True)
except BaseException as e:
    state['candidate_failed_phase']=state.get('candidate_phase');state['candidate_error_type']=type(e).__name__;phase('NEEDS_INSPECTION')
    print('cross-db unconfirmed; retained',rid,type(e).__name__,str(e),flush=True);raise
finally:
    os.close(lock)
    if bound and not clean:print('instances may remain; inspect recorded identity',rid,flush=True)
