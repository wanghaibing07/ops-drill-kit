#!/usr/bin/env python3
"""Install fixed OrderGuard unit and Nginx files, without starting services."""
import sys
sys.dont_write_bytecode=True
import argparse,fcntl,hashlib,os,pwd,stat
from pathlib import Path
sys.path.insert(0,str(Path(os.path.abspath(__file__)).parent))
import common as c

SERVICE=b'''[Unit]
Description=OrderGuard FastAPI Service
After=network.target

[Service]
Type=exec
User=devops
Group=devops
WorkingDirectory=/opt/ops-drill-kit
ExecStart=/opt/ops-drill-kit/.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=3
UMask=0027
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
'''
NGINX=b'''server {
    listen 127.0.0.1:8080;
    server_name localhost;
    access_log /var/log/nginx/orderguard-access.log;
    access_log /var/log/nginx/orderguard-timing.log orderguard_timing;
    add_header X-Request-ID $request_id always;
    error_log /var/log/nginx/orderguard-error.log warn;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Request-ID $request_id;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 3s;
        proxy_read_timeout 10s;
    }
}
'''
TIMING=b'''log_format orderguard_timing escape=json '{"request_id":"$request_id","method":"$request_method","status":"$status","request_time":"$request_time","upstream_connect_time":"$upstream_connect_time","upstream_response_time":"$upstream_response_time"}';
'''
TEMPLATES={
 '/etc/systemd/system/orderguard-api.service':(SERVICE,'c9362aa8adfcf34cf6ff30f68aedd4aee3416c51be92fc2ec7cf81fcc6ee3983'),
 '/etc/nginx/conf.d/00-orderguard-timing.conf':(TIMING,'bcf8e284fd4255874312fd762757737a07af6dceb0490e0c423fe7797709b1b7'),
 '/etc/nginx/conf.d/orderguard.conf':(NGINX,'e5c190f4703e5917eca726d3679fc4daadabfbbb65c95927732a5a444606f513')}

def inspect(path,content):
    if not os.path.lexists(path):return 'create'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        st=os.fstat(stream.fileno());data=stream.read(65537)
    if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1
            or st.st_mode&0o022 or st.st_size>65536 or len(data)>65536):
        raise c.Refusal('目标文件不安全')
    return 'same' if data==content else 'conflict'

def plan(targets):
    result={}
    for name,(content,digest) in targets.items():
        if hashlib.sha256(content).hexdigest()!=digest:raise c.Refusal('内置模板摘要不匹配')
        path=Path(name);c.chain(path.parent)
        result[name]=inspect(path,content)
    return result

def create_only(targets,actions):
    if 'conflict' in actions.values():raise c.Refusal('存在冲突；未创建或覆盖文件')
    for name,(content,_) in targets.items():
        if actions[name]!='create':continue
        path=Path(name);c.chain(path.parent)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            st=os.fstat(directory)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise c.Refusal('目标目录不安全')
            fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644,dir_fd=directory)
            with os.fdopen(fd,'wb') as stream:
                stream.write(content);stream.flush();os.fchmod(stream.fileno(),0o644);os.fsync(stream.fileno())
            os.fsync(directory)
        finally:os.close(directory)

def preflight():
    c.guard()
    for file in (Path(os.path.abspath(__file__)),Path(os.path.abspath(c.__file__))):
        c.chain(file.parent);c.regular(file)
    if hashlib.sha256(Path(c.__file__).read_bytes()).hexdigest()!='de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4':
        raise c.Refusal('共享检查模块版本不匹配')
    pwd.getpwnam('devops')
    for name in ('app/main.py','app/stage3_api.py','app/bounded_pool.py','app/n03_slow.py'):
        p=c.PROJECT/name
        if not p.is_file():raise c.Refusal('应用源码不完整')
    if not (c.PROJECT/'.venv/bin/python').is_file():raise c.Refusal('Python 环境缺失')
    return plan(TEMPLATES)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--apply',action='store_true');args=parser.parse_args(argv)
    try:
        actions=preflight()
        for name,status in actions.items():print(name+': '+status)
        if 'conflict' in actions.values():raise c.Refusal('存在冲突；未创建或覆盖文件')
        if not args.apply:return 0
        c.chain(c.STATE.parent)
        try:c.STATE.mkdir(mode=0o700)
        except FileExistsError:pass
        c.chain(c.STATE)
        if stat.S_IMODE(c.STATE.lstat().st_mode)!=0o700:raise c.Refusal('状态目录权限不安全')
        fd=os.open(c.STATE/'deploy.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600:
                raise c.Refusal('锁文件不安全')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            actions=preflight()
            create_only(TEMPLATES,actions)
        finally:os.close(fd)
        print('配置文件已核验；尚未重载或启动服务。')
        return 0
    except (c.Refusal,OSError,ValueError,KeyError) as exc:
        print('拒绝或失败:',str(exc) if isinstance(exc,c.Refusal) else type(exc).__name__,file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
