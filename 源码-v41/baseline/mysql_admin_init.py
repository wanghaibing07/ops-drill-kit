#!/usr/bin/env python3
"""Candidate: initialize an uninitialized local MySQL RPM service once.

Strictly requires this pinned stock config, empty datadir, absent error log and
admin credential. Failure is retained for manual inspection, never auto-retried.
"""
import sys
sys.dont_write_bytecode=True
import argparse,fcntl,hashlib,importlib.util,json,os,pwd,re,secrets,stat,string,subprocess,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(os.path.abspath(__file__)).parent))
import common as c

HERE=Path(os.path.abspath(__file__)).parent
MYSQL_IMPORT_SHA='de9a72de14b066488c4f6267dea7cac904408cfee937e5964c0fffa12cee4808'
COMMON_SHA='de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4'
VERIFY_SHA='440c4d5f98f1146c62c28725760430c66f371b0a5207b0bef8c6bb821d444df8'
STOCK_SHA='9c8b66aec85e40c595bd1b3324db589622aed377cc56bb69d237baeba4fcb302'
CONFIG=Path('/etc/my.cnf');DATA=Path('/var/lib/mysql');LOG=Path('/var/log/mysqld.log')
SOCKET='/var/lib/mysql/mysql.sock';JOURNAL=c.STATE/'mysql-admin-init.json'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C','MYSQL_HISTFILE':'/dev/null'}
SUFFIX=b'\n# ops-drill-kit: restrict MySQL lab listeners to loopback\n[mysqld]\nbind-address=127.0.0.1\nmysqlx-bind-address=127.0.0.1\n'

def run(args,*,input=None,pass_fds=(),timeout=30):
    p=subprocess.run(args,input=input,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,
                     pass_fds=pass_fds,timeout=timeout,check=False)
    if p.returncode:raise c.Refusal('MySQL 初始化阶段未确认；保留现场')
    return p.stdout

def preflight():
    c.guard();c.chain(HERE)
    for name,expected in (('common.py',COMMON_SHA),('mysql_import.py',MYSQL_IMPORT_SHA),('verify',VERIFY_SHA)):
        p=HERE/name;c.regular(p)
        if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise c.Refusal('组件摘要不匹配')
    c.regular(Path(os.path.abspath(__file__)))
    c.chain(CONFIG.parent);st=c.regular(CONFIG)
    if hashlib.sha256(CONFIG.read_bytes()).hexdigest()!=STOCK_SHA:raise c.Refusal('MySQL 配置不是已核对的原始版本')
    if any(os.path.lexists(path) for path in ('/etc/sysconfig/mysql','/etc/mysql/my.cnf','/usr/etc/my.cnf')):
        raise c.Refusal('存在额外 MySQL 环境或选项配置')
    c.chain(DATA.parent)
    stdata=DATA.lstat();mysql=pwd.getpwnam('mysql')
    if not stat.S_ISDIR(stdata.st_mode) or stdata.st_uid!=mysql.pw_uid or any(DATA.iterdir()):raise c.Refusal('MySQL 数据目录非空或身份不符')
    c.chain(LOG.parent)
    log_id=None
    if os.path.lexists(LOG):
        ls=LOG.lstat()
        if (not stat.S_ISREG(ls.st_mode) or ls.st_uid!=mysql.pw_uid or ls.st_nlink!=1
                or stat.S_IMODE(ls.st_mode)!=0o640 or ls.st_size!=0):
            raise c.Refusal('已有 MySQL 日志不符合空文件条件')
        log_id=(ls.st_dev,ls.st_ino)
    if os.path.lexists(c.ADMIN) or os.path.lexists(JOURNAL):raise c.Refusal('凭据或初始化记录已存在')
    p=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','mysqld.service'],env=ENV,timeout=10)
    if p.returncode!=3:raise c.Refusal('MySQL 服务状态不是明确停止')
    p=subprocess.run(['/usr/bin/systemctl','show','mysqld.service','-p','FragmentPath','--value'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=10)
    if p.returncode or p.stdout.strip()!=b'/usr/lib/systemd/system/mysqld.service':raise c.Refusal('MySQL 单元身份不符合预期')
    p=subprocess.run(['/usr/bin/systemctl','show','mysqld.service','-p','DropInPaths','--value'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=10)
    if p.returncode or p.stdout.strip():raise c.Refusal('MySQL 单元存在额外配置')
    return st,log_id

def verify_socket_owner(pid):
    out=run(['/usr/sbin/ss','-xlpn'],timeout=10)
    lines=[line for line in out.decode('utf8').splitlines() if SOCKET in line.split()]
    if len(lines)!=1 or not re.search(r'\bpid='+re.escape(pid)+r'(?:,|\))',lines[0]):raise c.Refusal('MySQL socket 进程身份不匹配')

def save(state,create=False):
    data=(json.dumps(state,sort_keys=True)+'\n').encode()
    if create:
        fd=os.open(JOURNAL,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    else:
        c.protected(JOURNAL);fd,tmp=tempfile.mkstemp(prefix='.mysql-init-',dir=c.STATE)
        try:
            with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fchmod(f.fileno(),0o600);os.fsync(f.fileno())
            os.replace(tmp,JOURNAL)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    fd=os.open(c.STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def password():
    alphabet=string.ascii_letters+string.digits+'_-'
    chars=[secrets.choice(string.ascii_lowercase),secrets.choice(string.ascii_uppercase),secrets.choice(string.digits),secrets.choice('_-')]
    chars.extend(secrets.choice(alphabet) for _ in range(44));secrets.SystemRandom().shuffle(chars)
    return ''.join(chars).encode('ascii')

def temp_password(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid not in (0,pwd.getpwnam('mysql').pw_uid) or st.st_mode&0o022 or st.st_size>8*1024*1024:
            raise c.Refusal('MySQL 日志文件身份不安全')
        data=f.read(8*1024*1024+1)
    matches=re.findall(rb'A temporary password is generated for root@localhost: ([^\r\n]+)',data)
    if len(matches)!=1 or not 1<=len(matches[0])<=128 or any(x<33 or x>126 for x in matches[0]):raise c.Refusal('临时管理员密码无法确定')
    return matches[0]

def rotate(socket,temporary,new):
    if not hasattr(os,'memfd_create'):raise c.Refusal('安全内存描述符不可用')
    if not re.fullmatch(rb'[A-Za-z0-9_-]{48}',new):raise c.Refusal('新凭据格式无效')
    fd=os.memfd_create('opsdrill-bootstrap',os.MFD_CLOEXEC)
    try:
        os.fchmod(fd,0o600)
        secret=temporary.replace(b'\\',b'\\\\').replace(b'"',b'\\"')
        data=b'[client]\npassword="'+secret+b'"\n';offset=0
        while offset<len(data):
            n=os.write(fd,data[offset:])
            if n<=0:raise c.Refusal('内存凭据写入失败')
            offset+=n
        os.lseek(fd,0,os.SEEK_SET)
        args=['/usr/bin/mysql','--defaults-file=/proc/self/fd/'+str(fd),'--user=root','--host=localhost',
              '--protocol=SOCKET','--socket='+socket,'--connect-expired-password','--skip-reconnect','--connect-timeout=3']
        run(args,input=b"ALTER USER 'root'@'localhost' IDENTIFIED BY '"+new+b"';\n",pass_fds=(fd,),timeout=30)
    finally:os.close(fd)

def install_config(st):
    old=CONFIG.read_bytes()
    if hashlib.sha256(old).hexdigest()!=STOCK_SHA:raise c.Refusal('配置已变化')
    backup=c.STATE/'mysql-stock-my.cnf'
    fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:f.write(old);f.flush();os.fsync(f.fileno())
    fd,tmp=tempfile.mkstemp(prefix='.opsdrill-mysql-',dir=CONFIG.parent)
    with os.fdopen(fd,'wb') as f:
        f.write(old+SUFFIX);f.flush();os.fchown(f.fileno(),st.st_uid,st.st_gid);os.fchmod(f.fileno(),stat.S_IMODE(st.st_mode));os.fsync(f.fileno())
    if hashlib.sha256(CONFIG.read_bytes()).hexdigest()!=STOCK_SHA:raise c.Refusal('配置已变化；临时文件保留')
    os.replace(tmp,CONFIG)
    run(['/usr/sbin/restorecon',str(CONFIG)],timeout=20)
    run(['/usr/sbin/mysqld','--validate-config','--user=mysql'],timeout=30)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true')
    parser.add_argument('--actor',choices=('agent','user'));args=parser.parse_args(argv)
    try:
        preflight();print('MySQL 首次初始化前置条件通过；默认只读。')
        if not args.apply:return 0
        if not args.actor:raise c.Refusal('--apply 必须明确 actor')
        c.chain(c.STATE.parent)
        try:c.STATE.mkdir(mode=0o700)
        except FileExistsError:pass
        c.chain(c.STATE)
        if stat.S_IMODE(c.STATE.lstat().st_mode)!=0o700:raise c.Refusal('状态目录不安全')
        fd=os.open(c.STATE/'deploy.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:raise c.Refusal('锁不安全')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);config_stat,log_id=preflight()
            state={'version':1,'actor':args.actor,'status':'RUNNING','phase':'CONFIGURING'};save(state,create=True)
            install_config(config_stat)
            state['phase']='STARTING';save(state)
            run(['/usr/bin/systemctl','start','mysqld.service'],timeout=120)
            spec=importlib.util.spec_from_file_location('bootstrap_identity',HERE/'mysql_import.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            process=module.process_identity()
            if (Path('/proc')/process[2]/'cmdline').read_bytes()!=b'/usr/sbin/mysqld\0':
                raise c.Refusal('MySQL 启动参数超出支持范围')
            from importlib.machinery import SourceFileLoader
            loader=SourceFileLoader('bootstrap_verify',str(HERE/'verify'))
            validator=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader));loader.exec_module(validator)
            if validator.mysql_listeners()[0]!='PASS':raise c.Refusal('MySQL 监听范围不安全')
            verify_socket_owner(process[2])
            if log_id is not None:
                current=LOG.lstat()
                if (current.st_dev,current.st_ino)!=log_id:raise c.Refusal('MySQL 日志文件已替换')
            temporary=temp_password(LOG);new=password()
            try:c.OPS.mkdir(mode=0o700)
            except FileExistsError:pass
            c.chain(c.OPS)
            if stat.S_IMODE(c.OPS.lstat().st_mode)!=0o700:raise c.Refusal('凭据目录不安全')
            state['phase']='PASSWORD_CHANGING';save(state)
            fd2=os.open(c.ADMIN,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            with os.fdopen(fd2,'wb') as f:
                f.write(b'[client]\nuser=root\npassword='+new+b'\nhost=localhost\nprotocol=SOCKET\nsocket='+SOCKET.encode()+b'\n');f.flush();os.fsync(f.fileno())
            fd2=os.open(c.OPS,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd2);os.close(fd2)
            if module.process_identity()!=process:raise c.Refusal('MySQL 进程发生变化')
            verify_socket_owner(process[2])
            rotate(SOCKET,temporary,new)
            if module.process_identity()!=process:raise c.Refusal('MySQL 进程发生变化')
            result=run(['/usr/bin/mysql','--defaults-file='+str(c.ADMIN),'--host=localhost','--protocol=SOCKET','--socket='+SOCKET,
                        '--batch','--raw','--skip-column-names','--skip-reconnect'],
                       input=b'SELECT CURRENT_USER(),@@datadir,@@socket,@@version,@@GLOBAL.local_infile,@@GLOBAL.general_log,@@GLOBAL.log_raw;\n')
            values=result.strip().split(b'\t')
            if len(values)!=7 or values[:3]!=[b'root@localhost',b'/var/lib/mysql/',SOCKET.encode()] or not re.fullmatch(rb'8\.4\.\d+(?:[-+][A-Za-z0-9._+-]+)?',values[3]) or values[4:]!=[b'0',b'0',b'0']:
                raise c.Refusal('初始化后身份或安全选项不符')
            if module.process_identity()!=process:raise c.Refusal('MySQL 进程发生变化')
            verify_socket_owner(process[2])
            state['phase']='VERIFYING';save(state)
            run(['/usr/bin/systemctl','enable','mysqld.service'],timeout=30)
            state['status']='DONE';save(state)
            print('MySQL 管理员初始化完成；尚未安装数据或应用。')
        finally:os.close(fd)
        return 0
    except (c.Refusal,OSError,ValueError,KeyError,subprocess.SubprocessError):
        print('MySQL 初始化未完成；保留配置、日志、凭据和状态，不自动重试。',file=sys.stderr)
        return 2
if __name__=='__main__':sys.exit(main())
