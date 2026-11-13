#!/usr/bin/env python3
"""Prepare the two fixed local app accounts using protected credential files."""
import sys
sys.dont_write_bytecode=True
import argparse,fcntl,hashlib,importlib.machinery,importlib.util,os,re,secrets,stat,string,subprocess
from pathlib import Path
sys.path.insert(0,str(Path(os.path.abspath(__file__)).parent))
import common as c

VERIFY_SHA='440c4d5f98f1146c62c28725760430c66f371b0a5207b0bef8c6bb821d444df8'
COMMON_SHA='de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4'
SOCKET='/var/lib/mysql/mysql.sock'
USERS=('orderguard_app','orderguard_stage3_reader')
FILES=(c.LEGACY_PASSWORD,c.READER_PASSWORD)
EXPECTED_GRANTS={
 'orderguard_app':{"GRANT USAGE ON *.* TO `orderguard_app`@`localhost`",
                   "GRANT SELECT, INSERT, UPDATE, DELETE ON `orderguard`.* TO `orderguard_app`@`localhost`"},
 'orderguard_stage3_reader':{"GRANT USAGE ON *.* TO `orderguard_stage3_reader`@`localhost`",
                            "GRANT SELECT ON `orderguard_stage3`.`orders` TO `orderguard_stage3_reader`@`localhost`"}}
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C','MYSQL_HISTFILE':'/dev/null'}

def admin_command():
    return ['/usr/bin/mysql','--defaults-file='+str(c.ADMIN),'--host=localhost','--protocol=SOCKET',
            '--socket='+SOCKET,'--batch','--raw','--skip-column-names','--skip-reconnect','--connect-timeout=3']

def admin(sql):
    cp=subprocess.run(admin_command(),input=sql,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                      timeout=30,env=ENV,check=False)
    if cp.returncode:raise c.Refusal('数据库检查或账号操作未确认；保留现场')
    return cp.stdout

def protected_password(path):
    c.protected(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());value=f.read(130)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:
        raise c.Refusal('凭据文件不安全')
    value=value.rstrip(b'\r\n')
    if not 1<=len(value)<=128 or any(x<32 or x==127 for x in value):raise c.Refusal('凭据文件格式不受支持')
    try:value.decode('utf8')
    except UnicodeDecodeError:raise c.Refusal('凭据文件格式不受支持') from None
    return value

def login_probe(user,password,*,reader_count=500000):
    if user not in USERS or not isinstance(password,bytes) or not 1<=len(password)<=128 or any(x<32 or x==127 for x in password):
        raise c.Refusal('账号检查输入无效')
    if type(reader_count) is not int or reader_count<0:raise c.Refusal('账号检查输入无效')
    if not hasattr(os,'memfd_create'):raise c.Refusal('内存凭据描述符不可用')
    fd=os.memfd_create('opsdrill-account-probe',os.MFD_CLOEXEC)
    try:
        escaped=password.replace(b'\\',b'\\\\').replace(b'"',b'\\"')
        os.fchmod(fd,0o600)
        data=b'[client]\npassword="'+escaped+b'"\n';offset=0
        while offset<len(data):
            written=os.write(fd,data[offset:])
            if written<=0:raise c.Refusal('内存凭据描述符写入失败')
            offset+=written
        os.lseek(fd,0,os.SEEK_SET)
        target='orderguard.orders' if user=='orderguard_app' else 'orderguard_stage3.orders'
        sql=('SELECT CURRENT_USER(),COUNT(*) FROM '+target+';\n').encode('ascii')
        args=['/usr/bin/mysql','--defaults-file=/proc/self/fd/'+str(fd),'--user='+user,'--host=localhost',
              '--protocol=SOCKET','--socket='+SOCKET,'--batch','--raw','--skip-column-names','--skip-reconnect','--connect-timeout=3']
        cp=subprocess.run(args,input=sql,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),
                          timeout=30,env=ENV,check=False)
        expected=(user+'@localhost\t'+('5' if user=='orderguard_app' else str(reader_count))).encode()
        if cp.returncode or cp.stdout.strip()!=expected:raise c.Refusal('账号认证或数据检查不匹配')
    finally:os.close(fd)

def verify_grants():
    for user in USERS:
        output=admin(("SHOW GRANTS FOR '"+user+"'@'localhost';\n").encode('ascii'))
        try:lines=output.decode('utf8').splitlines()
        except UnicodeError:raise c.Refusal('账号授权结果无法解析') from None
        if set(lines)!=EXPECTED_GRANTS[user] or len(lines)!=2:raise c.Refusal('账号授权不匹配')

def check_existing():
    verify_grants()
    for user,path in zip(USERS,FILES):login_probe(user,protected_password(path))

def safety_and_state():
    sql=(b"SELECT @@GLOBAL.general_log,@@GLOBAL.log_raw,"
         b"(SELECT COUNT(*) FROM information_schema.plugins WHERE LOWER(plugin_name) LIKE '%audit%' AND plugin_status='ACTIVE'),"
         b"(SELECT COUNT(*) FROM mysql.component WHERE LOWER(component_urn) LIKE '%audit%'),"
         b"(SELECT COUNT(*) FROM performance_schema.replication_connection_configuration),"
         b"(SELECT COUNT(*) FROM orderguard.orders),(SELECT COUNT(*) FROM orderguard_stage3.orders),"
         b"(SELECT COUNT(*) FROM mysql.user WHERE User IN ('orderguard_app','orderguard_stage3_reader')) ,"
         b"(SELECT COUNT(*) FROM mysql.user WHERE User IN ('orderguard_app','orderguard_stage3_reader') AND Host='localhost');\n")
    values=admin(sql).strip().split(b'\t')
    if len(values)!=9 or any(not x.isdigit() for x in values):raise c.Refusal('数据库前置检查无法解析')
    nums=list(map(int,values))
    if nums[:5]!=[0,0,0,0,0] or nums[5:7]!=[5,500000]:
        raise c.Refusal('日志、复制或固定数据前置条件不满足')
    present=[os.path.lexists(path) for path in FILES]
    if nums[7:]==[0,0] and present==[False,False]:return 'create'
    if nums[7:]==[2,2] and present==[True,True]:
        check_existing();return 'same'
    raise c.Refusal('账号或凭据处于部分存在状态；请检查，不覆盖')

def generate_password():
    alphabet=string.ascii_letters+string.digits+'_-'
    chars=[secrets.choice(string.ascii_lowercase),secrets.choice(string.ascii_uppercase),
           secrets.choice(string.digits),secrets.choice('_-')]
    chars.extend(secrets.choice(alphabet) for _ in range(44));secrets.SystemRandom().shuffle(chars)
    return ''.join(chars).encode('ascii')

def apply_create():
    passwords=[generate_password(),generate_password()]
    for path,value in zip(FILES,passwords):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,'wb') as f:f.write(value);f.flush();os.fsync(f.fileno())
    fd=os.open(c.OPS,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    sql=(b'SET SESSION sql_log_bin=0;\n'
         b"CREATE USER 'orderguard_app'@'localhost' IDENTIFIED BY '"+passwords[0]+b"';\n"
         b"GRANT SELECT, INSERT, UPDATE, DELETE ON orderguard.* TO 'orderguard_app'@'localhost';\n"
         b"CREATE USER 'orderguard_stage3_reader'@'localhost' IDENTIFIED BY '"+passwords[1]+b"';\n"
         b"GRANT SELECT ON orderguard_stage3.orders TO 'orderguard_stage3_reader'@'localhost';\n")
    admin(sql)
    check_existing()

def preflight():
    c.guard()
    for path in (Path(os.path.abspath(__file__)),Path(os.path.abspath(c.__file__))):c.chain(path.parent);c.regular(path)
    common=Path(c.__file__)
    if hashlib.sha256(common.read_bytes()).hexdigest()!=COMMON_SHA:raise c.Refusal('共享检查模块版本不匹配')
    validator=Path(os.path.abspath(__file__)).with_name('verify');c.chain(validator.parent);c.regular(validator)
    if hashlib.sha256(validator.read_bytes()).hexdigest()!=VERIFY_SHA:raise c.Refusal('选项文件校验器版本不匹配')
    loader=importlib.machinery.SourceFileLoader('opsdrill_accounts_verify',str(validator))
    spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module)
    module.check_admin_options()
    return safety_and_state()

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true');args=parser.parse_args(argv)
    try:
        state=preflight();print('应用与只读账号:',state)
        if not args.apply or state=='same':return 0
        c.chain(c.STATE.parent)
        try:c.STATE.mkdir(mode=0o700)
        except FileExistsError:pass
        c.chain(c.STATE)
        if stat.S_IMODE(c.STATE.lstat().st_mode)!=0o700:raise c.Refusal('状态目录权限不安全')
        fd=os.open(c.STATE/'deploy.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:raise c.Refusal('锁文件不安全')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if preflight()=='create':apply_create()
        finally:os.close(fd)
        print('账号及凭据已核验。')
        return 0
    except (c.Refusal,OSError,ValueError,UnicodeError,subprocess.SubprocessError):
        print('账号准备未完成；保留现场，不覆盖或自动删除。',file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
