"""Shared safety checks for the local baseline tools (Linux only)."""
import os
from pathlib import Path
import stat
import subprocess

PROJECT = Path('/opt/ops-drill-kit')
BASELINE = PROJECT / 'baseline'
MARKER = Path('/etc/opsdrill-lab')
OPS = Path('/etc/opsdrill')
ADMIN = OPS / 'mysql-admin.cnf'
LEGACY_PASSWORD = OPS / 'orderguard-app.password'
READER_PASSWORD = OPS / 'orderguard-stage3-reader.password'
DROPINS = Path('/etc/systemd/system/orderguard-api.service.d')
STATE = Path('/var/lib/opsdrill-baseline')


class Refusal(Exception):
    pass


def directory(path):
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Refusal('不安全目录')


def chain(path):
    for part in reversed((path, *path.parents)):
        directory(part)


def observed_chain(path):
    """Validate directory types without imposing root ownership on observations."""
    for part in reversed((path, *path.parents)):
        if not stat.S_ISDIR(part.lstat().st_mode):
            raise Refusal('观察路径中存在非目录或符号链接')


def regular(path, private=False):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != 0:
        raise Refusal('不安全文件')
    if private and (st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o600):
        raise Refusal('凭据权限不符合 root:root 0600')
    if not private and st.st_mode & 0o022:
        raise Refusal('文件可被组或其他用户写入')
    return st


def protected(path):
    chain(path.parent)
    regular(path, private=True)


def command(args, input_bytes=None, timeout=8):
    # Never inherit mysql-related configuration, proxy, environment secrets, or HOME.
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent',
           'LC_ALL': 'C', 'MYSQL_HISTFILE': '/dev/null'}
    try:
        result = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env,
                                timeout=timeout, check=False)
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, b''


def marker_ok():
    try:
        chain(MARKER.parent)
        regular(MARKER)
        return MARKER.read_bytes() in (b'ops-drill-kit', b'ops-drill-kit\n')
    except (OSError, Refusal):
        return False


def vm_ok():
    rc, out = command(['systemd-detect-virt', '--vm'])
    return rc == 0 and out.strip() == b'vmware'


def guard():
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise Refusal('需要 root')
    if not marker_ok() or not vm_ok():
        raise Refusal('VMware 或实验机标记检查失败')
    observed_chain(PROJECT)
    observed_chain(BASELINE)
