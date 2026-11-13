#!/usr/bin/env python3
"""Experimental stack orchestrator; requires provisioned OS, MySQL and venv.

Dry-run is read-only.  An interrupted apply is retained and refused on rerun;
it does not claim to recover or roll back MySQL DDL or service changes.
"""
import sys
sys.dont_write_bytecode=True
import argparse,fcntl,hashlib,json,os,pwd,stat,subprocess,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(os.path.abspath(__file__)).parent))
import common as c

HASHES={'common.py':'de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4',
        'verify':'440c4d5f98f1146c62c28725760430c66f371b0a5207b0bef8c6bb821d444df8',
        'deploy':'674741bc5062385356e3526a3f04b7d929325f558a99a7f5e56b991bcb9c440b',
        'db_batch.py':'27d28157251fc2dc55527acbb785399f32f398a1641b25860e834d1646abceb4',
        'mysql_import.py':'de9a72de14b066488c4f6267dea7cac904408cfee937e5964c0fffa12cee4808',
        'accounts.py':'36cda599f164bce46eb4e75becf6efd2878cd1a8411c10c5bc8fb84b5a42240e',
        'stack_files.py':'6e7fa2594f0c283ba076438637123fc72c37074e3a9f9932b09bf4dbea5a1855'}
SEED_SHA='a28047d53fc35dd2ca5b2662f41cc9d0963d0da0eb820f4142763d9f36a19883'
HERE=Path(os.path.abspath(__file__)).parent
JOURNAL=c.STATE/'orchestrator.json'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C','MYSQL_HISTFILE':'/dev/null'}

def check_files():
    c.guard();c.chain(HERE);c.regular(Path(os.path.abspath(__file__)))
    for name,digest in HASHES.items():
        p=HERE/name;c.regular(p)
        if hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise c.Refusal('受保护组件摘要不匹配')
    seed=c.PROJECT/'baseline/seed_orders.py'
    if hashlib.sha256(seed.read_bytes()).hexdigest()!=SEED_SHA:raise c.Refusal('造数程序摘要不匹配')
    pwd.getpwnam('devops')
    if not (c.PROJECT/'.venv/bin/python').is_file():raise c.Refusal('应用虚拟环境缺失')
    for path in ('/usr/bin/mysql','/usr/sbin/nginx','/usr/sbin/runuser'):
        if not Path(path).is_file():raise c.Refusal('系统依赖缺失')
    c.protected(c.ADMIN)
    p=subprocess.run(['/usr/sbin/getenforce'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=10)
    if p.returncode or p.stdout.strip()!=b'Enforcing':raise c.Refusal('SELinux 不是 Enforcing')
    p=subprocess.run(['/usr/sbin/getsebool','httpd_can_network_connect'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=10)
    if p.returncode or p.stdout.strip()!=b'httpd_can_network_connect --> on':raise c.Refusal('Nginx SELinux 网络访问尚未准备')
    p=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','mysqld.service'],env=ENV,timeout=10)
    if p.returncode:raise c.Refusal('MySQL 未运行')

def call(args,timeout=300,pass_fds=()):
    p=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,pass_fds=pass_fds)
    if p.returncode:raise c.Refusal('阶段失败；保留状态，需检查')
    return p.stdout

def read_state():
    if not os.path.lexists(JOURNAL):return None
    c.protected(JOURNAL)
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate key')
            result[key]=value
        return result
    raw=JOURNAL.read_bytes()
    if len(raw)>32768:raise c.Refusal('部署状态过大')
    state=json.loads(raw,object_pairs_hook=unique)
    if not isinstance(state,dict) or state.get('version')!=1:raise c.Refusal('部署状态无效')
    return state

def save_state(state,create=False):
    raw=(json.dumps(state,sort_keys=True)+'\n').encode()
    if create:
        fd=os.open(JOURNAL,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    else:
        c.protected(JOURNAL)
        fd,tmp=tempfile.mkstemp(prefix='.orchestrator-',dir=c.STATE)
        try:
            with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fchmod(f.fileno(),0o600);os.fsync(f.fileno())
            os.replace(tmp,JOURNAL)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    fd=os.open(c.STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def tool(name,*args,lockfd=None):
    if lockfd is None:
        code="import sys,runpy;sys.path.insert(0,sys.argv[1]);sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name='__main__')"
        return ['/usr/bin/python3','-I','-B','-c',code,str(HERE),str(HERE/name),*args]
    code="""import os,sys,stat,fcntl,runpy
fd=int(sys.argv[1]); path=sys.argv[2]; base=sys.argv[3]; target=sys.argv[4]
held=os.fstat(fd); named=os.lstat(path)
if not stat.S_ISREG(held.st_mode) or held.st_uid!=0 or held.st_nlink!=1 or stat.S_IMODE(held.st_mode)!=0o600 or (held.st_dev,held.st_ino)!=(named.st_dev,named.st_ino):raise RuntimeError('inherited deployment lock mismatch')
fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
original=fcntl.flock
def inherited_lock(other,operation):
    current=os.fstat(other)
    if (current.st_dev,current.st_ino)==(held.st_dev,held.st_ino):
        latest=os.lstat(path)
        if operation!=fcntl.LOCK_EX|fcntl.LOCK_NB or (latest.st_dev,latest.st_ino)!=(held.st_dev,held.st_ino):raise RuntimeError('deployment lock changed')
        return None
    return original(other,operation)
fcntl.flock=inherited_lock
sys.path.insert(0,base);sys.argv=[target]+sys.argv[5:];runpy.run_path(target,run_name='__main__')"""
    return ['/usr/bin/python3','-I','-B','-c',code,str(lockfd),str(c.STATE/'deploy.lock'),str(HERE),str(HERE/name),*args]

def phases(actor,lockfd=None):
    return [
      ('seed',['/usr/sbin/runuser','-u','devops','--','/usr/bin/python3','-B',str(c.PROJECT/'baseline/seed_orders.py'),'--apply'],300),
      ('mysql',tool('mysql_import.py','--apply','--actor',actor,lockfd=lockfd),1800),
      ('accounts',tool('accounts.py','--apply',lockfd=lockfd),120),
      ('stack_files',tool('stack_files.py','--apply',lockfd=lockfd),60),
      ('systemd_reload_before_credentials',['/usr/bin/systemctl','daemon-reload'],30),
      ('credentials',tool('deploy','--apply',lockfd=lockfd),60),
      ('systemd_reload',['/usr/bin/systemctl','daemon-reload'],30),
      ('nginx_config_test',['/usr/sbin/nginx','-t'],30),
      ('api_start',['/usr/bin/systemctl','start','orderguard-api.service'],60),
      ('nginx_start',['/usr/bin/systemctl','start','nginx.service'],60),
      ('enable_services',['/usr/bin/systemctl','enable','orderguard-api.service','nginx.service'],60),
      ('verify',tool('verify'),90)]

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true')
    parser.add_argument('--actor',choices=('agent','user'));args=parser.parse_args(argv)
    try:
        check_files()
        state=read_state()
        if state is not None and (state.get('status')!='DONE' or state.get('phase')!='verify'):
            raise c.Refusal('部署记录未完成，拒绝自动重试')
        print('前置检查通过；本入口不安装系统包、初始化 MySQL 管理员或建立 Python 环境。')
        print('执行顺序:',', '.join(x[0] for x in phases(args.actor or 'agent')))
        if not args.apply:return 0
        if not args.actor:raise c.Refusal('--apply 必须明确 actor')
        c.chain(c.STATE.parent)
        try:c.STATE.mkdir(mode=0o700)
        except FileExistsError:pass
        c.chain(c.STATE)
        if stat.S_IMODE(c.STATE.lstat().st_mode)!=0o700:raise c.Refusal('状态目录不安全')
        fd=os.open(c.STATE/'orchestrator.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:raise c.Refusal('编排锁不安全')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            deploy_fd=os.open(c.STATE/'deploy.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            try:
                dst=os.fstat(deploy_fd)
                if not stat.S_ISREG(dst.st_mode) or dst.st_uid!=0 or dst.st_nlink!=1 or stat.S_IMODE(dst.st_mode)!=0o600:raise c.Refusal('部署锁不安全')
                fcntl.flock(deploy_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                check_files();state=read_state()
                if state is not None:
                    if state.get('status')!='DONE' or state.get('phase')!='verify':raise c.Refusal('部署记录未完成，拒绝自动重试')
                    call(tool('verify'),90)
                    print('既有部署验证通过；未重做阶段。');return 0
                # A running nginx lacking this config requires a reload and is not adopted.
                active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','nginx.service'],env=ENV,timeout=10).returncode==0
                if active and not Path('/etc/nginx/conf.d/orderguard.conf').exists():raise c.Refusal('运行中的 Nginx 缺少配置；不接管')
                state={'version':1,'actor':args.actor,'status':'RUNNING','phase':'preparing'};save_state(state,create=True)
                for name,cmd,timeout in phases(args.actor,deploy_fd):
                    state['phase']=name;save_state(state)
                    print('执行阶段:',name,flush=True)
                    call(cmd,timeout,pass_fds=() if name=='seed' else (deploy_fd,))
                state['status']='DONE';save_state(state)
                print('业务栈阶段完成；不代表干净系统从零部署验收。')
            finally:os.close(deploy_fd)
        finally:os.close(fd)
        return 0
    except (c.Refusal,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print('编排未完成；保留现场：',str(exc) if isinstance(exc,c.Refusal) else type(exc).__name__,file=sys.stderr)
        return 2
if __name__=='__main__':sys.exit(main())
