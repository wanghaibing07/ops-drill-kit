#!/usr/bin/env python3
"""N01 candidate supervisor. Linux only; review before use."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path('/run/opsdrill-n01')
STATE = ROOT / 'state.json'
SOCK = ROOT / 'control.sock'
N02 = Path('/usr/local/libexec/opsdrill/n02/n02.py')
N02_SHA = 'a22e59d0217ab059b6c32f985094f074d8d553a273c2d3a2cc4065360d3120dc'
SELF = Path('/usr/local/libexec/opsdrill/n01/n01.py')
TTL = 180
CHILD_TTL = 210
IP = '/usr/sbin/ip'
PYTHON = '/usr/bin/python3'


class Refused(Exception): pass


def secure_file(path, digest=None):
    for p in (path, *path.parents):
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused('untrusted path: ' + str(p))
        if p != path and not stat.S_ISDIR(st.st_mode): raise Refused('invalid parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_size > 1048576:
            raise Refused('untrusted controller')
        data = f.read(1048577)
    if digest and hashlib.sha256(data).hexdigest() != digest: raise Refused('controller version mismatch')
    return data


def n02_module():
    secure_file(N02, N02_SHA)
    spec = importlib.util.spec_from_file_location('n02_reviewed', N02)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def root_dir():
    try: ROOT.mkdir(mode=0o700)
    except FileExistsError: pass
    st = ROOT.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise Refused('unsafe state directory')


def atomic_state(obj):
    tmp = ROOT / ('state-' + secrets.token_hex(12))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(obj, f, sort_keys=True); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, STATE)
        fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if tmp.exists(): tmp.unlink()


def read_state():
    fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 8192:
            raise Refused('unsafe state')
        state = json.load(f)
    if (not isinstance(state, dict) or set(state) != {'version','run_id','pid','identity','n02_run_id'}
            or state['version'] != 1 or not re.fullmatch(r'[0-9a-f]{24}', state.get('run_id',''))
            or not re.fullmatch(r'[0-9a-f]{24}', state.get('n02_run_id',''))
            or type(state['pid']) is not int or state['pid'] < 2 or not isinstance(state['identity'], list)
            or len(state['identity']) != 3): raise Refused('invalid state')
    return state


def identity(pid):
    text = Path('/proc', str(pid), 'stat').read_text()
    start = int(text[text.rfind(')') + 2:].split()[19])
    return [start, Path('/proc', str(pid), 'ns/net').stat().st_ino, os.readlink('/proc/%d/exe' % pid)]


def child_ids(pid):
    return [int(p) for p in Path('/proc', str(pid), 'task', str(pid), 'children').read_text().split()]


class BoundedChild:
    def __init__(self, namespace, argv, inode, expected_exe):
        self.proc = subprocess.Popen([IP, 'netns', 'exec', namespace, '/usr/bin/timeout',
                                      '--signal=TERM', '--kill-after=2s', str(CHILD_TTL), *argv],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, close_fds=True)
        self.parent = None
        self.child = None
        try:
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                if self.proc.poll() is not None: raise Refused('service failed to start')
                try:
                    parent = identity(self.proc.pid)
                    children = child_ids(self.proc.pid)
                    if parent[1] == inode and parent[2] == '/usr/bin/timeout' and len(children) == 1:
                        child = identity(children[0])
                        if child[1] == inode and child[2] == expected_exe:
                            self.parent = parent
                            self.child = (children[0], child)
                            self.verify()
                            return
                except (OSError, ValueError): pass
                time.sleep(.05)
            raise Refused('cannot establish service process identity')
        except Exception:
            # Unverified processes are never signalled; timeout bounds their lifetime.
            raise

    def verify(self):
        if self.proc.poll() is not None or identity(self.proc.pid) != self.parent:
            raise Refused('service supervisor identity changed')
        if child_ids(self.proc.pid) != [self.child[0]] or identity(self.child[0]) != self.child[1]:
            raise Refused('service process identity changed')

    def stop(self):
        self.verify()
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
            raise Refused('pidfd support required')
        fd = os.pidfd_open(self.child[0])
        try:
            self.verify()
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally: os.close(fd)
        try: self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired: raise Refused('service did not exit; refusing further signals')


def probe(ns, resolver, argv, timeout=8):
    # A private mount namespace confines the resolv.conf bind to the probe.
    script = 'mount --make-rprivate / && mount --bind "$1" /etc/resolv.conf && shift && exec "$@"'
    cmd = [IP, 'netns', 'exec', ns, '/usr/bin/unshare', '--mount', '/bin/sh', '-c', script,
           'n01-probe', str(resolver), *argv]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env={'PATH':'/usr/sbin:/usr/bin', 'LC_ALL':'C'})


HTTP = 'from http.server import HTTPServer,BaseHTTPRequestHandler\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200); self.end_headers(); self.wfile.write(b"N01 OK")\nHTTPServer(("10.203.2.2",8080),H).serve_forever()'


def judge(direct, hosts, answer, domain):
    addresses = {line.split()[0] for line in hosts.stdout.splitlines() if line.split()}
    if direct.returncode: return 2, 'direct HTTP failed'
    if answer.returncode: return 2, 'DNS query failed'
    if hosts.returncode not in (0, 2): return 2, 'getent failed'
    if answer.stdout.split() != ['10.203.2.2'] or addresses != {'10.203.2.2'}:
        return 1, 'N01 DNS fault observed'
    if domain.returncode: return 2, 'domain HTTP failed'
    return 0, 'N01 DNS and HTTP verified'


def request(rid, action):
    state = read_state()
    if state['run_id'] != rid: raise Refused('run ID mismatch')
    before = identity(state['pid'])
    if before != state['identity'] or before[2] not in ('/usr/bin/python3', '/usr/bin/python3.9'):
        raise Refused('supervisor identity mismatch')
    st = SOCK.lstat()
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise Refused('unsafe control socket')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(45); s.connect(str(SOCK))
        import struct
        pid, uid, _ = struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0 or pid != state['pid'] or identity(pid) != before: raise Refused('control peer mismatch')
        s.sendall((json.dumps({'run_id':rid,'action':action})+'\n').encode())
        data = b''
        while b'\n' not in data and len(data) < 8192:
            chunk = s.recv(8192-len(data))
            if not chunk: break
            data += chunk
    reply = json.loads(data)
    if set(reply) != {'code','message'} or type(reply['code']) is not int: raise Refused('invalid response')
    print(reply['message'])
    return reply['code']


def worker():
    n02 = n02_module(); n02.guard()
    root_dir()
    if any(os.path.lexists(p) for p in (STATE, SOCK, ROOT/'resolv.conf')):
        raise Refused('existing N01 state or resources')
    if any(os.path.lexists('/etc/netns/'+name) for name in n02.NAMES):
        raise Refused('existing namespace configuration')
    n02.ROOT.mkdir(mode=0o700, exist_ok=True)
    st = n02.ROOT.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise Refused('unsafe N02 state directory')
    lock = n02.acquire_lock(fcntl)
    topology = None; dns = None; http = None; server = None; published = False; resolver_owned = False; socket_owned = False
    def cleanup_owned():
        nonlocal topology, dns, http, published, resolver_owned, socket_owned
        if published and read_state() != state: raise Refused('state identity changed')
        if socket_owned:
            st = SOCK.lstat()
            if not stat.S_ISSOCK(st.st_mode) or (st.st_dev, st.st_ino) != socket_identity:
                raise Refused('control socket identity changed')
        if resolver_owned:
            st = (ROOT/'resolv.conf').lstat()
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1
                    or stat.S_IMODE(st.st_mode) != 0o600 or (st.st_dev, st.st_ino) != resolver_identity):
                raise Refused('resolver file identity changed')
        if topology is not None:
            n02.validate_owned(topology, complete=True); n02.check_table(topology, 'baseline')
        if dns is not None: dns.stop(); dns = None
        if http is not None: http.stop(); http = None
        if topology is not None: n02.cleanup(topology); topology = None
        if resolver_owned:
            st = (ROOT/'resolv.conf').lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
                raise Refused('resolver file identity changed')
            if (st.st_dev, st.st_ino) != resolver_identity: raise Refused('resolver file replaced')
            (ROOT/'resolv.conf').unlink(); resolver_owned = False
        if published:
            if read_state() != state: raise Refused('state identity changed')
            STATE.unlink(); published = False
        if socket_owned:
            st = SOCK.lstat()
            if not stat.S_ISSOCK(st.st_mode) or (st.st_dev, st.st_ino) != socket_identity:
                raise Refused('control socket identity changed')
            SOCK.unlink(); socket_owned = False
    try:
        topology = n02.setup()
        rid = secrets.token_hex(12)
        resolver = ROOT/'resolv.conf'
        fd = os.open(resolver, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            st = os.fstat(f.fileno()); resolver_identity = (st.st_dev, st.st_ino); resolver_owned = True
            f.write('nameserver 10.203.1.1\noptions timeout:1 attempts:1\n')
        def new_dns(address):
            return BoundedChild('od-router', ['/usr/sbin/dnsmasq','--keep-in-foreground','--no-resolv',
                  '--no-hosts','--bind-interfaces','--listen-address=10.203.1.1',
                  '--address=/app.lab/'+address], topology['namespaces']['od-router'], '/usr/sbin/dnsmasq')
        http = BoundedChild('od-server', [PYTHON,'-u','-c',HTTP], topology['namespaces']['od-server'], os.path.realpath(PYTHON))
        dns = new_dns('10.203.2.99')
        # Confirm the actual DNS response and the direct HTTP path before issuing a receipt.
        deadline = time.monotonic()+5
        while True:
            direct = probe('od-client', resolver, ['/usr/bin/curl','--noproxy','*','--fail','--silent','--max-time','2','http://10.203.2.2:8080/'])
            answer = probe('od-client', resolver, ['/usr/bin/dig','+short','+time=1','+tries=1','@10.203.1.1','app.lab','A'])
            if direct.returncode == 0 and answer.returncode == 0 and answer.stdout.split() == ['10.203.2.99']: break
            if time.monotonic() >= deadline: raise Refused('fault baseline could not be confirmed')
            time.sleep(.1)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(SOCK)); os.chmod(SOCK, 0o600); server.listen(2); server.setblocking(False)
        st = SOCK.lstat(); socket_identity = (st.st_dev, st.st_ino); socket_owned = True
        state = {'version':1, 'run_id':rid, 'n02_run_id':topology['run_id'], 'pid':os.getpid(), 'identity':identity(os.getpid())}
        atomic_state(state); published = True
        print(json.dumps({'receipt':'N01_OWNER_V1','run_id':rid}), flush=True)
        deadline = time.monotonic()+TTL
        repaired = False
        while time.monotonic() < deadline:
            ready, _, _ = select.select([server], [], [], min(1, max(0, deadline-time.monotonic())))
            if not ready: continue
            conn, _ = server.accept()
            with conn:
                conn.settimeout(2)
                try:
                    import struct
                    _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid != 0: raise Refused('root peer required')
                    data = b''
                    while b'\n' not in data and len(data) < 1024:
                        chunk = conn.recv(1024-len(data))
                        if not chunk: break
                        data += chunk
                    req = json.loads(data)
                    if set(req) != {'run_id','action'} or req['run_id'] != rid: raise Refused('request identity mismatch')
                    n02.validate_owned(topology, complete=True); n02.check_table(topology, 'baseline')
                    dns.verify(); http.verify()
                    action = req['action']
                    if action == 'verify-owner': code, message = 0, 'N01 owner verified'
                    elif action == 'repair':
                        if not repaired:
                            dns.stop(); dns = None
                            dns = new_dns('10.203.2.2'); repaired = True
                        code, message = 0, 'N01 DNS record restored'
                    elif action == 'check':
                        direct = probe('od-client', resolver, ['/usr/bin/curl','--noproxy','*','--fail','--silent','--max-time','3','http://10.203.2.2:8080/'])
                        hosts = probe('od-client', resolver, ['/usr/bin/getent','ahostsv4','app.lab'])
                        answer = probe('od-client', resolver, ['/usr/bin/dig','+short','+time=1','+tries=1','@10.203.1.1','app.lab','A'])
                        domain = probe('od-client', resolver, ['/usr/bin/curl','--noproxy','*','--fail','--silent','--max-time','3','http://app.lab:8080/'])
                        code, message = judge(direct, hosts, answer, domain)
                    elif action == 'reset':
                        cleanup_owned()
                        code, message = 0, 'N01 reset completed'
                    else: raise Refused('unknown action')
                except (OSError, subprocess.SubprocessError) as exc: code, message = 2, 'N01 probe failed: '+str(exc)
                except Exception as exc: code, message = 3, 'N01 refused: '+str(exc)
                conn.sendall((json.dumps({'code':code,'message':message})+'\n').encode())
                if code == 0 and req['action'] == 'reset': break
    finally:
        if server is not None: server.close()
        # Refuse rather than kill a process whose PID, executable or namespace changed.
        try:
            cleanup_owned()
        except Exception as exc:
            print('N01 cleanup refused; inspect protected state: '+str(exc), file=sys.stderr, flush=True)
        finally: os.close(lock)


def main():
    p = argparse.ArgumentParser(); p.add_argument('action', choices=('inject','start','worker','check','repair','reset','verify-owner','inspect-clean')); p.add_argument('run_id', nargs='?')
    a = p.parse_args()
    n02 = n02_module(); n02.guard(); root_dir()
    secure_file(SELF)
    if a.action == 'worker':
        if a.run_id: raise Refused('unexpected run ID')
        return worker()
    if a.action == 'inspect-clean':
        if a.run_id: raise Refused('unexpected run ID')
        if any(os.path.lexists(p) for p in (STATE, SOCK, ROOT/'resolv.conf')): raise Refused('N01 resources remain')
        n02.ROOT.mkdir(mode=0o700, exist_ok=True)
        st = n02.ROOT.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
            raise Refused('unsafe N02 state directory')
        fd = n02.acquire_lock(fcntl)
        try:
            if any(os.path.lexists(p) for p in (STATE, SOCK, ROOT/'resolv.conf')): raise Refused('N01 resources remain')
            if n02.load() is not None or set(n02.NAMES) & n02.namespaces(): raise Refused('N02 resources remain')
            return 0
        finally: os.close(fd)
    if a.action in ('start','inject'):
        if a.run_id: raise Refused('unexpected run ID')
        proc = subprocess.Popen([PYTHON, str(SELF), 'worker'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                start_new_session=True, close_fds=True)
        ready, _, _ = select.select([proc.stdout], [], [], 20)
        if not ready: raise Refused('supervisor startup timed out; inspect state')
        line = proc.stdout.readline()
        receipt = json.loads(line)
        if set(receipt) != {'receipt','run_id'} or receipt['receipt'] != 'N01_OWNER_V1' or not re.fullmatch(r'[0-9a-f]{24}',receipt['run_id']):
            raise Refused('invalid supervisor receipt')
        print(line, end=''); return 0
    if not a.run_id or not re.fullmatch(r'[0-9a-f]{24}',a.run_id): raise Refused('run ID required')
    if a.action == 'reset' and not os.path.lexists(STATE):
        if any(os.path.lexists(p) for p in (SOCK, ROOT/'resolv.conf')): raise Refused('ambiguous N01 resources')
        n02.ROOT.mkdir(mode=0o700, exist_ok=True)
        st = n02.ROOT.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
            raise Refused('unsafe N02 state directory')
        fd = n02.acquire_lock(fcntl)
        try:
            if n02.load() is not None or set(n02.NAMES) & n02.namespaces(): raise Refused('ambiguous N02 resources')
            print('N01 already clean'); return 0
        finally: os.close(fd)
    return request(a.run_id, a.action)


if __name__ == '__main__':
    try: sys.exit(main() or 0)
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('N01 refused or failed: '+str(exc), file=sys.stderr); sys.exit(3)
