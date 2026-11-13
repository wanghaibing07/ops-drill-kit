#!/usr/bin/env python3
"""Read-only validation of the lab's Nginx log rotation policy."""
import os
import re
import stat
import subprocess
from pathlib import Path

POLICY = Path('/etc/logrotate.d/nginx')
TARGETS = ('/var/log/nginx/orderguard-access.log', '/var/log/nginx/orderguard-error.log')


class PolicyError(Exception):
    pass


def require(ok, code):
    if not ok:
        raise PolicyError(code)


def read_policy():
    fd = os.open(POLICY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= 16384, 'UNSAFE_LOGROTATE_CONFIG')
        data = os.read(fd, 16385)
        require(len(data) <= 16384, 'UNSAFE_LOGROTATE_CONFIG')
        return data, (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    finally:
        os.close(fd)


def validate_policy(data):
    try:
        lines = [line.strip() for line in data.decode('utf-8').splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
    except UnicodeError:
        raise PolicyError('LOGROTATE_CONFIG_ENCODING')
    require(lines and lines[0] == '/var/log/nginx/*.log {' and lines[-1] == '}', 'LOGROTATE_SCOPE')
    require(sum(line == 'postrotate' for line in lines) == 1 and
            sum(line == 'endscript' for line in lines) == 1, 'LOGROTATE_REOPEN_MISSING')
    start, end = lines.index('postrotate'), lines.index('endscript')
    require(start < end and sum(line in ('{', '}') for line in lines) == 1, 'LOGROTATE_CONFIG_SHAPE')
    directives = lines[1:start] + lines[end + 1:-1]
    require(any(re.fullmatch(r'rotate\s+[1-9][0-9]*', line) for line in directives), 'LOGROTATE_RETENTION')
    require(any(re.fullmatch(r'(daily|weekly|monthly|size\s+\S+|maxsize\s+\S+)', line) for line in directives),
            'LOGROTATE_SCHEDULE')
    script = lines[start + 1:end]
    require(any(re.match(r'^(?:/bin/kill|kill)\s+-USR1\s+', line) and
                re.search(r'\bcat\s+/run/nginx\.pid\b', line) for line in script), 'LOGROTATE_REOPEN_MISSING')


def validate_output(nginx, debug):
    for directive, target in zip(('access_log', 'error_log'), TARGETS):
        require(re.search(r'^\s*' + directive + r'\s+' + re.escape(target) + r'(?:\s|;)', nginx, re.MULTILINE),
                'NGINX_LOG_TARGET_MISSING')
        require(re.search(r'^considering log ' + re.escape(target) + r'\s*$', debug, re.MULTILINE),
                'LOGROTATE_TARGET_MISSING')
    require(re.search(r'^rotating pattern: /var/log/nginx/\*\.log\s', debug, re.MULTILINE), 'LOGROTATE_SCOPE')


def verify():
    data, identity = read_policy()
    validate_policy(data)
    env = dict(os.environ, LC_ALL='C')
    nginx = subprocess.run(['/usr/sbin/nginx', '-T'], stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, env=env, timeout=15, check=False)
    require(nginx.returncode == 0, 'NGINX_CONFIG_INVALID')
    rotate = subprocess.run(['/usr/sbin/logrotate', '--debug', '--force', '--state', '/dev/null', str(POLICY)],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=15, check=False)
    require(rotate.returncode == 0, 'LOGROTATE_CONFIG_INVALID')
    validate_output(nginx.stdout, rotate.stderr)
    after, after_identity = read_policy()
    require(data == after and identity == after_identity, 'LOGROTATE_CONFIG_CHANGED')
