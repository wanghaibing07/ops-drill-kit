#!/usr/bin/env python3
"""Experimental clean-VM bootstrap; requires reviewed project and tool staging.

This has not been tested on a clean VM. It preserves failed state and refuses
automatic retry. The expected DMI product UUID must be independently confirmed.
"""
import sys
sys.dont_write_bytecode=True
import argparse,ast,fcntl,hashlib,json,os,pwd,re,stat,subprocess,tempfile
from pathlib import Path

HERE=Path(os.path.abspath(__file__)).parent
PROJECT=Path('/opt/ops-drill-kit');MARKER=Path('/etc/opsdrill-lab')
STATE=Path('/var/lib/opsdrill-bootstrap');JOURNAL=STATE/'run.json'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C','MYSQL_HISTFILE':'/dev/null'}
TOOLS={'common.py':'de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4',
       'verify':'440c4d5f98f1146c62c28725760430c66f371b0a5207b0bef8c6bb821d444df8',
       'mysql_import.py':'de9a72de14b066488c4f6267dea7cac904408cfee937e5964c0fffa12cee4808',
       'mysql_admin_init.py':'f15a9ad7a72bd045e3ad925da7bb7f98bc29995528350a43451c6d92e908c7a7',
       'orchestrate.py':'8777a4d359e5b34ca85181024b17fa08913510f6ffa6435c6c5800ca2f3db88d',
       'install_drill_runtimes.py':'192357cd3f9ab1c064878cdfa4f42f317f8f8735781454c6250f798e32e9b3ef'}

class Refusal(Exception):pass

def trusted_dir(path):
    for part in reversed((path,*path.parents)):
        st=part.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise Refusal('不安全的受保护目录')

def trusted_file(path):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022:raise Refusal('不安全的受保护文件')

def run(args,timeout=120):
    p=subprocess.run(args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,check=False)
    if p.returncode:raise Refusal('阶段未确认；保留现场')
    return p.stdout

def stage_tool(name,*args):
    code="import sys,runpy;sys.path.insert(0,sys.argv[1]);sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name='__main__')"
    return ['/usr/bin/python3','-I','-B','-c',code,str(HERE),str(HERE/name),*args]

M04_SOURCE=HERE.parent/'experimental/m04/synthetic-v4'
M04_INSTALLER=M04_SOURCE/'install_v4.py'
M04_INSTALLER_SHA='3b9326d042e9e98af67ad8e7fa271f068ec0a045d3561cbf359d71d0fe71c7ad'
M04_PARENT=Path('/usr/local/libexec/opsdrill')

def m04_preflight():
    trusted_dir(M04_SOURCE); trusted_dir(M04_SOURCE/'continuation'); trusted_file(M04_INSTALLER)
    raw=M04_INSTALLER.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=M04_INSTALLER_SHA: raise Refusal('M04 安装器摘要不匹配')
    tree=ast.parse(raw); assignments=[node for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MANIFEST' for t in node.targets)]
    if len(assignments)!=1: raise Refusal('M04 清单无效')
    manifest=ast.literal_eval(assignments[0].value)
    if not isinstance(manifest,dict) or len(manifest)!=14: raise Refusal('M04 清单无效')
    for name,digest in manifest.items():
        if not re.fullmatch(r'(?:continuation/)?[a-z0-9_]+\.py',name) or not re.fullmatch(r'[0-9a-f]{64}',digest): raise Refusal('M04 清单路径无效')
        path=M04_SOURCE/name; trusted_file(path)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=digest: raise Refusal('M04 源码摘要不匹配')
    trusted_dir(M04_PARENT.parent)
    if os.path.lexists(M04_PARENT): trusted_dir(M04_PARENT)
    if os.path.lexists(M04_PARENT/'m04-synthetic-v4'): raise Refusal('M04 v4 已存在；不覆盖')

def install_m04():
    m04_preflight()
    try: M04_PARENT.mkdir(mode=0o755)
    except FileExistsError: pass
    trusted_dir(M04_PARENT)
    run(['/usr/bin/python3','-I','-B',str(M04_INSTALLER),'--source',str(M04_SOURCE)],120)

M02_V2_SOURCE=HERE.parent/'drills/mysql/M02/baseline-v2'
M02_V2_PINS={'m02_deadlock.py':'11e7e49054d660e521dc5aa0b0c2dab146bd6f9509634d5166e461d83a295b6c',
             'm02_launcher.py':'f0f0550f68b0d38792f42534f6408825c882083afe0e14315e5449d15dd2b2c8',
             'install_m02_v2.py':'7d0407eb1fd507143e713e1662adc04c42b09a4d92ca28a858244a1615f00338',
             'bootstrap_m02_writer_v2.py':'2591d350b13db8386b66361ad25df602cafdee6178a9e31562724b54f59e3045'}
def m02_v2_preflight():
    trusted_dir(M02_V2_SOURCE)
    for name,digest in M02_V2_PINS.items():
        path=M02_V2_SOURCE/name;trusted_file(path)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise Refusal('M02 v2 组件摘要不匹配')
    if os.path.lexists('/usr/local/libexec/opsdrill/m02-baseline-v2'):raise Refusal('M02 v2 目标已存在；不覆盖')

def preflight(expected_uuid):
    if os.geteuid()!=0:raise Refusal('需要 root')
    if run(['/usr/bin/systemd-detect-virt','--vm'],10).strip()!=b'vmware':raise Refusal('目标不是 VMware 虚拟机')
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',expected_uuid):raise Refusal('VM 标识格式无效')
    actual=Path('/sys/class/dmi/id/product_uuid').read_text(encoding='ascii').strip().lower()
    if actual!=expected_uuid:raise Refusal('VM 标识不匹配')
    osinfo=Path('/etc/os-release').read_text(encoding='utf8')
    if not re.search(r'(?m)^ID=["\']?rocky["\']?$',osinfo) or not re.search(r'(?m)^VERSION_ID=["\']?9(?:\.[0-9]+)?["\']?$',osinfo):raise Refusal('仅支持 Rocky Linux 9')
    trusted_dir(HERE);trusted_file(Path(os.path.abspath(__file__)))
    for name,digest in TOOLS.items():
        path=HERE/name;trusted_file(path)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise Refusal('受保护组件摘要不匹配')
    for name in ('deploy','db_batch.py','accounts.py','stack_files.py'):
        trusted_file(HERE/name)
    m04_preflight()
    m02_v2_preflight()
    inspect_n03_slow_dropin()
    user=pwd.getpwnam('devops')
    st=PROJECT.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=user.pw_uid or st.st_mode&0o022:raise Refusal('项目目录身份不符')
    if os.path.lexists(MARKER):
        trusted_dir(MARKER.parent);trusted_file(MARKER)
        if MARKER.read_bytes() not in (b'ops-drill-kit',b'ops-drill-kit\n'):raise Refusal('实验标记冲突')
    if os.path.lexists(JOURNAL):raise Refusal('已有初始化记录；必须检查，不自动重试')
    if os.path.lexists(PROJECT/'.venv'):raise Refusal('项目虚拟环境已存在；不覆盖')
    if os.path.lexists('/etc/opsdrill/mysql-admin.cnf'):raise Refusal('MySQL 管理员凭据已存在；不覆盖')

def save(state,create=False):
    data=(json.dumps(state,sort_keys=True)+'\n').encode()
    if create:
        fd=os.open(JOURNAL,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    else:
        trusted_file(JOURNAL);fd,tmp=tempfile.mkstemp(prefix='.bootstrap-',dir=STATE)
        try:
            with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fchmod(f.fileno(),0o600);os.fsync(f.fileno())
            os.replace(tmp,JOURNAL)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    fd=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def create_marker():
    if os.path.lexists(MARKER):return
    trusted_dir(MARKER.parent)
    fd=os.open(MARKER,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
    with os.fdopen(fd,'wb') as f:f.write(b'ops-drill-kit\n');f.flush();os.fsync(f.fileno())

def ensure_lab_dirs():
    for path in (Path('/mnt/opsdrill'),Path('/var/lib/opsdrill')):
        trusted_dir(path.parent)
        try:path.mkdir(mode=0o700)
        except FileExistsError:pass
        trusted_dir(path)
        if stat.S_IMODE(path.lstat().st_mode)!=0o700:raise Refusal('实验状态目录权限不符')

def ensure_contract_evidence_dirs(parent=Path('/var')):
    """Create only root-controlled evidence directories, never fix unsafe ones."""
    trusted_dir(parent)
    for part in ('backups','opsdrill'):
        parent=parent/part
        try:parent.mkdir(mode=0o700)
        except FileExistsError:pass
        trusted_dir(parent)
    for drill in ('M02','M03','M04','C01'):
        child=parent/drill
        try:child.mkdir(mode=0o700)
        except FileExistsError:pass
        trusted_dir(child)


N03_SLOW_DROPIN=b'[Service]\nEnvironment=OPSDRILL_ENABLE_SLOW=1\n'

def inspect_n03_slow_dropin(parent=Path('/etc/systemd/system')):
    """Plan only the gated local slow endpoint; reject conflicts and links."""
    trusted_dir(parent)
    directory=parent/'orderguard-api.service.d'
    if not os.path.lexists(directory):return 'create-directory-and-file'
    trusted_dir(directory)
    target=directory/'40-opsdrill-n03.conf'
    if not os.path.lexists(target):return 'create-file'
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno());data=f.read(4097)
    if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022
            or len(data)>4096 or data!=N03_SLOW_DROPIN):
        raise Refusal('N03 慢接口配置冲突或不安全')
    return 'same'

def ensure_n03_slow_dropin(parent=Path('/etc/systemd/system')):
    """Create only the reviewed drop-in; never replace an existing file."""
    action=inspect_n03_slow_dropin(parent)
    directory=parent/'orderguard-api.service.d'
    if action=='create-directory-and-file':
        try:directory.mkdir(mode=0o755)
        except FileExistsError:pass
    trusted_dir(directory)
    if inspect_n03_slow_dropin(parent)=='same':return
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(dfd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise Refusal('N03 配置目录不安全')
        fd=os.open('40-opsdrill-n03.conf',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644,dir_fd=dfd)
        with os.fdopen(fd,'wb') as f:f.write(N03_SLOW_DROPIN);f.flush();os.fchmod(f.fileno(),0o644);os.fsync(f.fileno())
        os.fsync(dfd)
    finally:os.close(dfd)
    if inspect_n03_slow_dropin(parent)!='same':raise Refusal('N03 配置创建未确认')


def ensure_m02_dirs(state_root=Path('/var/lib/opsdrill'),project=PROJECT):
    """Prepare only the required M02 directories; refuse unsafe existing paths."""
    trusted_dir(state_root)
    target=state_root/'m02-deadlock'
    try:target.mkdir(mode=0o700)
    except FileExistsError:pass
    trusted_dir(target)
    st=target.lstat()
    if st.st_gid!=0 or stat.S_IMODE(st.st_mode)!=0o700:raise Refusal('M02 状态目录权限不符')
    user=pwd.getpwnam('devops')
    fd=os.open(project,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=user.pw_uid or st.st_mode&0o022:raise Refusal('项目目录身份不符')
        try:os.mkdir('evidence',mode=0o755,dir_fd=fd);created=True
        except FileExistsError:created=False
        child=os.open('evidence',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            st=os.fstat(child)
            if created:
                if st.st_uid!=0 or st.st_gid!=0:raise Refusal('M02 新证据目录身份不符')
                os.fchown(child,user.pw_uid,user.pw_gid);os.fchmod(child,0o755);st=os.fstat(child)
            if st.st_uid!=user.pw_uid or st.st_gid!=user.pw_gid or stat.S_IMODE(st.st_mode)!=0o755:
                raise Refusal('M02 证据目录权限不符')
        finally:os.close(child)
    finally:os.close(fd)


def configure_mysql_repo():
    # The pinned official release RPM currently selects 9.7 by default.
    repo=Path('/etc/yum.repos.d/mysql-community.repo');trusted_dir(repo.parent);trusted_file(repo)
    old=repo.read_bytes();digest='20ad8c1296a3eb342e9fb05df04cf02bf5a8dd429447e60d31ed623e2f6d5adb'
    if hashlib.sha256(old).hexdigest()!=digest:raise Refusal('MySQL 仓库原始配置不符')
    import configparser
    cfg=configparser.ConfigParser(interpolation=None);cfg.read_string(old.decode('utf8'))
    if (cfg.get('mysql-8.4-lts-community','gpgcheck',fallback='')!='1' or
        cfg.get('mysql-8.4-lts-community','gpgkey',fallback='')!='file:///etc/pki/rpm-gpg/RPM-GPG-KEY-mysql-2025'):
        raise Refusal('MySQL 仓库签名配置不符')
    backup=STATE/'mysql-community.repo.original'
    fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:f.write(old);f.flush();os.fsync(f.fileno())
    choices={'mysql-8.4-lts-community':'1','mysql-9.7-lts-community':'0','mysql-tools-8.4-lts-community':'1','mysql-tools-9.7-lts-community':'0'}
    section=None;seen=set();lines=[]
    for line in old.decode('utf8').splitlines(keepends=True):
        match=re.match(r'^\[([^]]+)\]',line)
        if match:section=match.group(1)
        if section in choices and re.match(r'^enabled\s*=',line):
            if section in seen:raise Refusal('仓库 enabled 字段重复')
            seen.add(section);line='enabled='+choices[section]+'\n'
        lines.append(line)
    if seen!=set(choices):raise Refusal('仓库节不完整')
    st=repo.lstat();fd,tmp=tempfile.mkstemp(prefix='.opsdrill-repo-',dir=repo.parent)
    with os.fdopen(fd,'wb') as f:
        f.write(''.join(lines).encode());f.flush();os.fchown(f.fileno(),st.st_uid,st.st_gid);os.fchmod(f.fileno(),stat.S_IMODE(st.st_mode));os.fsync(f.fileno())
    if hashlib.sha256(repo.read_bytes()).hexdigest()!=digest:raise Refusal('仓库配置发生变化')
    os.replace(tmp,repo);run(['/usr/sbin/restorecon',str(repo)],20)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--vm-uuid',required=True)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--actor',choices=('agent','user'));args=parser.parse_args(argv)
    try:
        preflight(args.vm_uuid.lower())
        print('干净 VM 前置检查通过；此候选依赖已安全传入的项目及工具。')
        if not args.apply:return 0
        if not args.actor:raise Refusal('--apply 必须明确 actor')
        trusted_dir(STATE.parent)
        try:STATE.mkdir(mode=0o700)
        except FileExistsError:pass
        trusted_dir(STATE)
        if stat.S_IMODE(STATE.lstat().st_mode)!=0o700:raise Refusal('状态目录权限不符')
        fd=os.open(STATE/'bootstrap.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:raise Refusal('锁不安全')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);preflight(args.vm_uuid.lower())
            state={'version':1,'actor':args.actor,'status':'RUNNING','phase':'marker','vm_uuid':args.vm_uuid.lower()};save(state,create=True)
            create_marker()
            state['phase']='lab_dirs';save(state);ensure_lab_dirs()
            state['phase']='evidence_dirs';save(state);ensure_contract_evidence_dirs()
            state['phase']='m02_dirs';save(state);ensure_m02_dirs()
            steps=[
              ('epel',['/usr/bin/dnf','-y','install','epel-release'],600),
              ('base_packages',['/usr/bin/dnf','-y','install','nginx','python3','python3-pip','python3-devel','policycoreutils-python-utils','nftables','dnsmasq','tcpdump','iproute','bind-utils','sysstat','lsof','git','curl','make','bats','ShellCheck','python3.11','python3.11-libs','python3.11-PyMySQL','python3.11-cryptography','python3.11-cffi','python3.11-pycparser'],1200),
              ('mysql_repo',['/usr/bin/dnf','-y','install','https://repo.mysql.com/mysql84-community-release-el9-4.noarch.rpm'],600),
              ('mysql_repo_config',None,0),
              ('mysql_rpm',['/usr/bin/dnf','-y','--enablerepo=mysql-8.4-lts-community','--disablerepo=mysql-9.7-lts-community','--disablerepo=mysql-tools-9.7-lts-community','install','mysql-community-server-8.4.13-1.el9'],1200),
              ('venv',['/usr/sbin/runuser','-u','devops','--','/usr/bin/python3','-m','venv',str(PROJECT/'.venv')],120),
              ('python_deps',['/usr/sbin/runuser','-u','devops','--',str(PROJECT/'.venv/bin/python'),'-m','pip','install','-r',str(PROJECT/'requirements.txt')],1200),
              ('selinux_network',['/usr/sbin/setsebool','-P','httpd_can_network_connect','1'],120),
              ('mysql_admin',stage_tool('mysql_admin_init.py','--apply','--actor',args.actor),300),
              ('m04_v4',None,0),
              ('drill_runtimes',stage_tool('install_drill_runtimes.py','--source-root',str(HERE.parent),'--apply','--actor',args.actor),1800),
              ('m02_v2_install',['/usr/bin/python3','-I','-B',str(M02_V2_SOURCE/'install_m02_v2.py'),str(M02_V2_SOURCE)],300),
              ('n03_slow_dropin',None,0),
              ('stack',stage_tool('orchestrate.py','--apply','--actor',args.actor),2400),
              ('m02_writer_v2',['/usr/bin/python3','-I','-B',str(M02_V2_SOURCE/'bootstrap_m02_writer_v2.py'),'create'],300)]
            for name,cmd,timeout in steps:
                state['phase']=name;save(state);print('执行阶段:',name,flush=True)
                if name=='mysql_repo_config':configure_mysql_repo()
                elif name=='m04_v4':install_m04()
                elif name=='n03_slow_dropin':ensure_n03_slow_dropin()
                else:run(cmd,timeout)
            state['status']='DONE';save(state);print('初始化执行完成；仍须单独验收首个演练。')
        finally:os.close(fd)
        return 0
    except (Refusal,OSError,ValueError,KeyError,subprocess.SubprocessError):
        print('初始化未完成；保留现场，不自动重试。',file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
