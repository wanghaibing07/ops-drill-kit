#!/usr/bin/env python3
"""N04 bounded, single-session network-namespace candidate (Linux only)."""
import errno
import json
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import sys
import threading
import time

SYSCTL = Path('/proc/sys/net/ipv4/ip_local_port_range')
NS = '/proc/self/ns/net'
LOW, HIGH = 40000, 40031
SERVER = ('127.0.0.2', 18080)
MAX_ATTEMPTS = 96
LIFETIME = 60
TIMEOUT = 0.4


def guard():
    if os.geteuid() != 0:
        raise RuntimeError('root required')
    fd = os.open('/etc/opsdrill-lab', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not (stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= 64 and
                os.read(fd, 65).strip() == b'ops-drill-kit'):
            raise RuntimeError('unsafe lab marker')
    finally:
        os.close(fd)
    result = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
                            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}, check=False)
    if result.returncode != 0 or result.stdout.strip() != 'vmware':
        raise RuntimeError('VMware guest required')


def port_range(text):
    parts = text.split()
    if len(parts) != 2 or not all(x.isascii() and x.isdigit() for x in parts):
        raise ValueError('invalid port range')
    low, high = map(int, parts)
    if not 1 <= low < high <= 65535:
        raise ValueError('invalid port range')
    return low, high


def namespace_identity(path):
    st = os.stat(path)
    return st.st_dev, st.st_ino


def require_isolation():
    own = namespace_identity(NS)
    parent = namespace_identity('/proc/%d/ns/net' % os.getppid())
    initial = namespace_identity('/proc/1/ns/net')
    if own == parent or own == initial:
        raise RuntimeError('isolated network namespace not proven')
    return own


def read_range():
    return port_range(SYSCTL.read_text(encoding='ascii'))


def set_range(value, expected_namespace):
    if require_isolation() != expected_namespace:
        raise RuntimeError('network namespace identity changed')
    low, high = value
    port_range('%d %d' % (low, high))
    SYSCTL.write_text('%d %d\n' % (low, high), encoding='ascii')
    if read_range() != value:
        raise RuntimeError('port range write not confirmed')


def timewait_count(text):
    count = 0
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != '06':
            continue
        try:
            local_ip, local_port = fields[1].split(':')
            remote_ip, remote_port = fields[2].split(':')
            if (local_ip == '0100007F' and remote_ip == '0200007F' and
                    LOW <= int(local_port, 16) <= HIGH and int(remote_port, 16) == SERVER[1]):
                count += 1
        except ValueError:
            raise RuntimeError('invalid TCP observation')
    return count


def server_loop(listener, stop):
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        with conn:
            conn.settimeout(TIMEOUT)
            try:
                while not stop.is_set():
                    data = conn.recv(1)
                    if not data:
                        break
                    conn.sendall(data)
            except (OSError, TimeoutError):
                pass


def exchange(conn):
    conn.sendall(b'x')
    if conn.recv(1) != b'x':
        raise RuntimeError('unexpected server response')


def short_connections(deadline):
    result = {'attempts': 0, 'completed': 0, 'address_unavailable': 0, 'other_errors': []}
    for _ in range(MAX_ATTEMPTS):
        if time.monotonic() >= deadline:
            break
        result['attempts'] += 1
        with socket.socket() as conn:
            conn.settimeout(TIMEOUT)
            try:
                conn.connect(SERVER)
                exchange(conn)
                conn.shutdown(socket.SHUT_WR)
                if conn.recv(1) != b'':
                    raise RuntimeError('unexpected trailing data')
                result['completed'] += 1
            except OSError as exc:
                if exc.errno == errno.EADDRNOTAVAIL:
                    result['address_unavailable'] += 1
                    break
                result['other_errors'].append(exc.errno or 'timeout')
                break
    return result


def reuse_connection():
    with socket.socket() as conn:
        conn.settimeout(TIMEOUT)
        conn.connect(SERVER)
        for _ in range(8):
            exchange(conn)
        conn.shutdown(socket.SHUT_WR)
        if conn.recv(1) != b'':
            raise RuntimeError('unexpected trailing data')
    return 8


def fault_evidence(result, count, observed_range):
    return (observed_range == (LOW, HIGH) and result['completed'] > 0 and
            result['address_unavailable'] > 0 and not result['other_errors'] and count > 0)


def emit(obj):
    print(json.dumps(obj, sort_keys=True), flush=True)


def worker():
    identity = require_isolation()
    original = read_range()
    if original[1] - original[0] + 1 < 1024:
        raise RuntimeError('namespace baseline range too narrow')
    deadline = time.monotonic() + LIFETIME
    listener = None
    stop = threading.Event()
    changed = False
    try:
        subprocess.run(['/usr/sbin/ip', 'link', 'set', 'dev', 'lo', 'up'], check=True,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=3)
        listener = socket.socket()
        listener.settimeout(TIMEOUT)
        listener.bind(SERVER)
        listener.listen(8)
        threading.Thread(target=server_loop, args=(listener, stop), daemon=True).start()
        # Mark before writing so cleanup also runs if post-write verification fails.
        changed = True
        set_range((LOW, HIGH), identity)
        churn = short_connections(min(deadline, time.monotonic() + 20))
        observed = timewait_count(Path('/proc/net/tcp').read_text(encoding='ascii'))
        emit({'event': 'injected', 'range': list(read_range()), 'churn': churn,
              'time_wait': observed, 'fault_proven': fault_evidence(churn, observed, read_range()),
              'expires_seconds': max(0, int(deadline-time.monotonic()))})
        repaired = False
        pending = b''
        while time.monotonic() < deadline:
            if b'\n' not in pending:
                ready, _, _ = select.select([sys.stdin], [], [], min(0.5, max(0, deadline-time.monotonic())))
                if not ready:
                    continue
                data = os.read(sys.stdin.fileno(), 256)
                if not data:
                    break
                pending += data
                if len(pending) > 1024:
                    raise RuntimeError('command input limit exceeded')
                continue
            line, pending = pending.split(b'\n', 1)
            action = line.decode('ascii').strip()
            if action == 'check':
                current = read_range()
                count = timewait_count(Path('/proc/net/tcp').read_text(encoding='ascii'))
                emit({'event': 'check', 'range': list(current), 'time_wait': count,
                      'fault_proven': fault_evidence(churn, count, current),
                      'repaired': repaired and current == original})
            elif action == 'repair':
                if read_range() not in ((LOW, HIGH), original):
                    raise RuntimeError('unexpected range drift')
                set_range(original, identity)
                repaired = reuse_connection() == 8
                emit({'event': 'repair', 'range_restored': read_range() == original,
                      'requests_on_one_connection': 8, 'reuse_passed': repaired})
            elif action == 'reset':
                break
            else:
                emit({'event': 'error', 'message': 'expected check, repair or reset'})
    finally:
        stop.set()
        if listener is not None:
            listener.close()
        if changed:
            current = read_range()
            if current not in ((LOW, HIGH), original):
                raise RuntimeError('range drift: refusing to overwrite')
            if current != original:
                set_range(original, identity)
        emit({'event': 'reset', 'range_restored': read_range() == original})


def controller():
    if sys.platform != 'linux':
        raise RuntimeError('Linux is required')
    initial = read_range()
    command = ['/usr/bin/unshare', '--net', '--', sys.executable, '-I', '-B',
               str(Path(__file__).resolve()), '--worker']
    child = subprocess.Popen(command, stdin=subprocess.PIPE, text=True)
    try:
        pending = b''
        while child.poll() is None:
            if b'\n' not in pending:
                ready, _, _ = select.select([sys.stdin], [], [], 0.5)
                if not ready:
                    continue
                data = os.read(sys.stdin.fileno(), 256)
                if not data:
                    break
                pending += data
                if len(pending) > 1024:
                    raise RuntimeError('command input limit exceeded')
                continue
            line, pending = pending.split(b'\n', 1)
            action = line.decode('ascii').strip()
            if action not in ('check', 'repair', 'reset'):
                print('expected check, repair or reset', file=sys.stderr, flush=True)
                continue
            child.stdin.write(action + '\n')
            child.stdin.flush()
            if action == 'reset':
                break
    except BrokenPipeError:
        pass
    finally:
        try:
            child.stdin.close()
        except BrokenPipeError:
            pass
        try:
            code = child.wait(timeout=LIFETIME+5)
        except subprocess.TimeoutExpired:
            # This is the direct child, not a PID loaded from persistent state.
            child.kill()
            child.wait()
            raise RuntimeError('worker did not exit within bound')
        current = read_range()
        emit({'event': 'controller_exit', 'worker_exit': code,
              'caller_namespace_range_unchanged': current == initial})
    return code if current == initial else 2


if __name__ == '__main__':
    try:
        guard()
        if Path(__file__).absolute() != Path('/usr/local/libexec/opsdrill/n04-recovery-v2/n04.py'):
            raise RuntimeError('untrusted installation path')
        if sys.argv[1:] == ['--worker']:
            worker()
        elif len(sys.argv) == 1:
            sys.exit(controller())
        else:
            raise ValueError('unsupported arguments')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('N04 refused:', exc, file=sys.stderr, flush=True)
        sys.exit(2)
