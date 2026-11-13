EXPECTED={'orders-500000-reference.tsv': (1, 500000, '283a3a0453f2d1945ad33e81a0425ee4cf51bc59d8553bb2936901641f66993b'), 'orders-50000-reference.tsv': (1, 50000, '9d3b71e677e1b9619069cee1064ca04e61376baf096a3793ab78ce01f31f2e16'), 'orders-1000-whole.tsv': (1, 1000, '14ac915c8ce2abd0e18ef22ea1bf7ee0ecb4b92de4c478e501c3d38aa851e6c8'), 'orders-1001-50000.tsv': (1001, 50000, '8a33eb1e84cd9a960820fddf0c1c871e4e7f01845df6bd34e0cf9985082199bd'), 'orders-50001-100000.tsv': (50001, 100000, '6250d5f820ec542c716c59049d814415edb819237ce3020d1968b4fe8d798018'), 'orders-100001-150000.tsv': (100001, 150000, '74864abbf242561f3949e57d643cafa400493422b4d688de305b62b7c6a2240a'), 'orders-150001-200000.tsv': (150001, 200000, 'f09bdd6a085133192b2544dd3a243f89a0bcbed35366dc2c40293d63fc3ae68c'), 'orders-200001-250000.tsv': (200001, 250000, '4725e7a48ae1b82ea929c0f7712964c15d8c2b9cb2c9c91caf1bdb1e32c50d96'), 'orders-250001-300000.tsv': (250001, 300000, 'ce4c368103906b78961c0abedafab60b9a17aa04f861783381137f86d48d7313'), 'orders-300001-350000.tsv': (300001, 350000, 'd42f276b7a35384bf2d8520d274387a40ca61eab40cbba57deeffadd36f3eb6f'), 'orders-350001-400000.tsv': (350001, 400000, 'd27ae6c529685081cb15ef60866775c04cbfd3e3ea91d30818a7393ab8d288be'), 'orders-400001-450000.tsv': (400001, 450000, 'ebe30c7015053d39295a27af4464827f5ad576aa62b77e50cbcbcae11862a5e0'), 'orders-450001-500000.tsv': (450001, 500000, '0d17cf15dee8f55be059f040da0bbd523202e731f40ad5e3d159cd20168ac31b')}
"""Guarded one-time bootstrap for empty local MySQL; existing data is never overwritten."""
import sys
sys.dont_write_bytecode=True
import argparse,fcntl,hashlib,importlib.machinery,importlib.util,json,os,pwd,re,secrets,stat,subprocess,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(os.path.abspath(__file__)).parent))
import common as c
import db_batch

SHA={'common.py':'de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4',
     'verify':'440c4d5f98f1146c62c28725760430c66f371b0a5207b0bef8c6bb821d444df8',
     'db_batch.py':'27d28157251fc2dc55527acbb785399f32f398a1641b25860e834d1646abceb4'}
SCHEMA={'sql/001_schema.sql':'c6e3ebd67dec6b3d8d0696a5c60ca1a399e140d4d5c09e0e89ae6c278d05211e',
        'sql/002_seed.sql':'8336418f46238d1361adcc1dcdde125518d39c9c514928934b614649e70027ba',
        'sql/003_stage3_schema.sql':'4b197c8b4ddaf777b12e54b37ac435ba72b7dee4e913ce1328f5b02607cf911e'}
DATA=Path('/var/tmp/ops-drill-kit')
JOURNAL=c.STATE/'database-init.json'
SOCKET='/var/lib/mysql/mysql.sock'
DATADIR='/var/lib/mysql/'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C','MYSQL_HISTFILE':'/dev/null'}
_PROCESS_IDENTITY=None

def file_bytes(path,digest,limit,uid=None,mode=None):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not (stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=limit
                and (uid is None or st.st_uid==uid) and (mode is None or stat.S_IMODE(st.st_mode)==mode)):
            raise c.Refusal('输入文件不安全')
        with os.fdopen(fd,'rb') as f:fd=-1;data=f.read(limit+1)
    finally:
        if fd>=0:os.close(fd)
    if len(data)>limit or hashlib.sha256(data).hexdigest()!=digest:raise c.Refusal('输入文件摘要不匹配')
    return data

def mysql_command():
    return ['/usr/bin/mysql','--defaults-file='+str(c.ADMIN),'--host=localhost','--protocol=SOCKET',
            '--socket='+SOCKET,'--batch','--raw','--skip-column-names','--skip-reconnect','--connect-timeout=3']

def sql(data,timeout=120):
    result=subprocess.run(mysql_command(),input=data,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          env=ENV,timeout=timeout,check=False)
    if result.returncode or len(result.stdout)>64*1024*1024:raise c.Refusal('数据库操作未确认；保留状态')
    return result.stdout

def process_identity():
    result=subprocess.run(['/usr/bin/systemctl','show','mysqld.service','-p','MainPID','-p','InvocationID','-p','ControlGroup'],
                          stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=10,check=False)
    if result.returncode:raise c.Refusal('MySQL 进程身份不可用')
    try:
        lines=result.stdout.decode('ascii').splitlines()
        pairs=[line.split('=',1) for line in lines]
        props=dict(pairs)
        if len(pairs)!=3 or len(props)!=3 or set(props)!={'MainPID','InvocationID','ControlGroup'}:raise ValueError
        pid=props['MainPID'];invocation=props['InvocationID']
        if (not re.fullmatch(r'[1-9][0-9]*',pid) or int(pid)<=1
                or not re.fullmatch(r'[0-9a-f]{32}',invocation) or invocation=='0'*32
                or props['ControlGroup']!='/system.slice/mysqld.service'):raise ValueError
        proc=Path('/proc')/pid;data=(proc/'stat').read_text(encoding='ascii')
        fields=data[data.rfind(')')+2:].split()
        if len(fields)<=19 or fields[0] in ('Z','X') or not fields[19].isdigit():raise ValueError
        if proc.stat().st_uid!=pwd.getpwnam('mysql').pw_uid:raise ValueError
        if (proc/'cgroup').read_text(encoding='ascii').strip()!='0::/system.slice/mysqld.service':raise ValueError
        if os.readlink(proc/'exe')!='/usr/sbin/mysqld':raise ValueError
        boot=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot):raise ValueError
    except (OSError,UnicodeError,ValueError,IndexError):
        raise c.Refusal('MySQL 进程身份不可验证') from None
    return boot,invocation,pid,fields[19]

def identity():
    global _PROCESS_IDENTITY
    process=process_identity()
    if _PROCESS_IDENTITY is not None and process!=_PROCESS_IDENTITY:raise c.Refusal('MySQL 进程已更换')
    data=sql(b'SELECT @@server_uuid,@@datadir,@@socket,@@version,@@GLOBAL.local_infile;\n',timeout=15).strip().split(b'\t')
    if process_identity()!=process:raise c.Refusal('MySQL 进程已更换')
    if len(data)!=5:raise c.Refusal('数据库身份无法解析')
    try:uuid,datadir,socket,version,infile=(x.decode('ascii') for x in data)
    except UnicodeError:raise c.Refusal('数据库身份无法解析') from None
    if (not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',uuid)
            or datadir!=DATADIR or socket!=SOCKET or not re.fullmatch(r'8\.4\.\d+(?:[-+][A-Za-z0-9._+-]+)?',version)
            or infile!='0'):
        raise c.Refusal('数据库身份、版本或 local_infile 不符合预期')
    if _PROCESS_IDENTITY is None:_PROCESS_IDENTITY=process
    return uuid

def unchanged(expected):
    if identity()!=expected:raise c.Refusal('数据库身份已变化')

def load_verifier():
    base=Path(os.path.abspath(__file__)).parent
    for name,digest in SHA.items():
        p=base/name;c.chain(p.parent);c.regular(p)
        if hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise c.Refusal('部署依赖摘要不匹配')
    loader=importlib.machinery.SourceFileLoader('baseline_import_verify',str(base/'verify'))
    spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module)
    module.check_admin_options()
    return module

def require_network(verifier):
    status,_=verifier.mysql_listeners()
    if status!='PASS':raise c.Refusal('MySQL 监听范围或进程身份不符合预期')

def batches_preflight():
    uid=pwd.getpwnam('devops').pw_uid;st=DATA.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=uid or stat.S_IMODE(st.st_mode)!=0o700:raise c.Refusal('合成数据目录不安全')
    batches=sorted((v[0],v[1],k,v[2]) for k,v in EXPECTED.items() if 'reference' not in k)
    previous=0
    for first,end,name,digest in batches:
        if first!=previous+1:raise c.Refusal('批次范围不连续')
        file_bytes(DATA/name,digest,8*1024*1024,uid,0o600);previous=end
    if previous!=500000:raise c.Refusal('批次范围不完整')
    return uid,batches

def schema_sources():
    return [file_bytes(c.PROJECT/name,digest,65536) for name,digest in SCHEMA.items()]

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate JSON key')
        result[key]=value
    return result

def read_journal():
    if not os.path.lexists(JOURNAL):return None
    c.chain(JOURNAL.parent);c.regular(JOURNAL,private=True)
    raw=JOURNAL.read_bytes()
    if len(raw)>131072:raise c.Refusal('数据库状态过大')
    try:obj=json.loads(raw,object_pairs_hook=unique_object)
    except (ValueError,UnicodeDecodeError):raise c.Refusal('数据库状态无效') from None
    if not isinstance(obj,dict) or obj.get('version')!=1:raise c.Refusal('数据库状态无效')
    return obj

def save_journal(state,create=False):
    raw=(json.dumps(state,sort_keys=True)+'\n').encode('utf8')
    if len(raw)>131072:raise c.Refusal('数据库状态过大')
    if create:
        fd=os.open(JOURNAL,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    else:
        c.protected(JOURNAL)
        fd,tmp=tempfile.mkstemp(prefix='.database-state-',dir=JOURNAL.parent)
        try:
            with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fchmod(f.fileno(),0o600);os.fsync(f.fileno())
            os.replace(tmp,JOURNAL)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    fd=os.open(JOURNAL.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)

def schema_signatures():
    result={}
    for name in ('orderguard.merchants','orderguard.orders','orderguard_stage3.merchants','orderguard_stage3.orders'):
        result[name]=hashlib.sha256(sql(('SHOW CREATE TABLE '+name+';\n').encode('ascii'),timeout=20)).hexdigest()
    return result

def verify_data(uuid):
    unchanged(uuid)
    counts=sql(b'SELECT (SELECT COUNT(*) FROM orderguard.orders),(SELECT COUNT(*) FROM orderguard_stage3.merchants),'
               b'(SELECT COUNT(*) FROM orderguard_stage3.orders),(SELECT COUNT(*) FROM orderguard_stage3.orders WHERE merchant_id=88);\n').strip()
    if counts!=b'5\t500\t500000\t25000':raise c.Refusal('基线数据数量不符合预期')
    output=sql(b'SELECT order_no,merchant_id,user_id,order_status,amount_cents,pay_channel,created_at,updated_at '
               b'FROM orderguard_stage3.orders ORDER BY id;\n',timeout=180)
    if hashlib.sha256(output).hexdigest()!=EXPECTED['orders-500000-reference.tsv'][2]:raise c.Refusal('全量数据摘要不匹配')
    signatures=schema_signatures();unchanged(uuid)
    return signatures

def preflight():
    c.guard();self_path=Path(os.path.abspath(__file__));c.chain(self_path.parent);c.regular(self_path)
    verifier=load_verifier();require_network(verifier);uuid=identity()
    uid,batches=batches_preflight();schema=schema_sources();state=read_journal()
    databases=sql(b"SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name IN ('orderguard','orderguard_stage3');\n",timeout=15).strip()
    if state is None:
        if databases!=b'0':raise c.Refusal('目标库已存在且无本工具完成记录；不覆盖')
        return 'create',uuid,uid,batches,schema,None
    if state.get('status')!='DONE' or state.get('server_uuid')!=uuid or databases!=b'2':
        raise c.Refusal('数据库状态未完成或身份不符；请检查，不重试')
    if (set(state)!={'version','run_id','actor','server_uuid','status','committed','schema_sha256'}
            or state.get('actor') not in ('agent','user')
            or not isinstance(state.get('run_id'),str)
            or not re.fullmatch(r'[0-9a-f]{24}',state['run_id'])
            or not isinstance(state.get('committed'),list)
            or len(state['committed'])!=len(batches)):
        raise c.Refusal('数据库完成记录无效')
    prefix=hashlib.sha256()
    for entry,(first,end,name,digest) in zip(state['committed'],batches):
        before=prefix.hexdigest()
        prefix.update(file_bytes(DATA/name,digest,8*1024*1024,uid,0o600))
        if entry!={'start':first,'end':end,'source_sha256':digest,
                   'before_sha256':before,'after_sha256':prefix.hexdigest()}:
            raise c.Refusal('数据库批次完成记录无效')
    if verify_data(uuid)!=state.get('schema_sha256'):raise c.Refusal('既有数据库结构与记录不匹配')
    return 'same',uuid,uid,batches,schema,state

def apply_new(uuid,uid,batches,schema,actor):
    if actor not in ('user','agent'):raise c.Refusal('执行者必须明确')
    unchanged(uuid)
    state={'version':1,'run_id':secrets.token_hex(12),'actor':actor,'server_uuid':uuid,'status':'SCHEMA_APPLYING','committed':[]}
    save_journal(state,create=True)
    sql(b'CREATE DATABASE orderguard CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;\n'+b'\n'.join(schema),timeout=60)
    unchanged(uuid)
    initial=sql(b'SELECT (SELECT COUNT(*) FROM orderguard.orders),(SELECT COUNT(*) FROM orderguard_stage3.merchants),'
                b'(SELECT COUNT(*) FROM orderguard_stage3.orders);\n',timeout=20).strip()
    if initial!=b'5\t500\t0':raise c.Refusal('初始结构或数据不符合预期')
    state['status']='IMPORTING';save_journal(state);prefix=hashlib.sha256()
    for first,end,name,digest in batches:
        raw=file_bytes(DATA/name,digest,8*1024*1024,uid,0o600);rows=db_batch.parse_batch(raw,first,end,digest)
        after=prefix.copy();after.update(raw)
        state['inflight']={'start':first,'end':end,'source_sha256':digest,
                           'before_sha256':prefix.hexdigest(),'after_sha256':after.hexdigest()}
        save_journal(state);unchanged(uuid)
        text="SET SESSION sql_mode='STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';\nSTART TRANSACTION;\n"
        text+=''.join(statement+'SELECT @@warning_count;\n' for statement in db_batch.statements(rows))+'COMMIT;\n'
        output=sql(text.encode('ascii'),timeout=180).decode('ascii').splitlines()
        if len(output)!=(len(rows)+499)//500 or any(x!='0' for x in output):raise c.Refusal('批次警告或结果不明')
        if sql(b'SELECT COUNT(*) FROM orderguard_stage3.orders;\n',timeout=30).strip()!=str(end).encode():
            raise c.Refusal('批次数量不匹配')
        unchanged(uuid);state['committed'].append(state.pop('inflight'));save_journal(state);prefix=after
        print('已导入合成订单:',first,'-',end,flush=True)
    state['status']='VERIFYING';save_journal(state)
    state['schema_sha256']=verify_data(uuid);state['status']='DONE';save_journal(state)
    return state['run_id']

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true')
    parser.add_argument('--actor',choices=('agent','user'));args=parser.parse_args(argv)
    try:
        action,uuid,uid,batches,schema,_=preflight();print('数据库初始化:',action,flush=True)
        if not args.apply or action=='same':return 0
        if not args.actor:raise c.Refusal('--apply 必须明确 --actor')
        c.chain(c.STATE.parent)
        try:c.STATE.mkdir(mode=0o700)
        except FileExistsError:pass
        c.chain(c.STATE)
        if stat.S_IMODE(c.STATE.lstat().st_mode)!=0o700:raise c.Refusal('状态目录不安全')
        fd=os.open(c.STATE/'deploy.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:raise c.Refusal('部署锁不安全')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            action,uuid,uid,batches,schema,_=preflight()
            if action=='create':print('数据库初始化完成:',apply_new(uuid,uid,batches,schema,args.actor))
        finally:os.close(fd)
        return 0
    except (c.Refusal,OSError,ValueError,UnicodeError,KeyError,subprocess.SubprocessError):
        print('数据库初始化未完成；保留现场，不覆盖或自动删除。',file=sys.stderr)
        return 2

if __name__=='__main__':sys.exit(main())
