#!/usr/bin/env python3
"""N02 candidate. All network writes are scoped to project network namespaces."""
import argparse
import json
import hashlib
import os
import pathlib
import re
import secrets
import select
import stat
import subprocess
import sys
import time

NAMES = ('od-client', 'od-router', 'od-server')
ROOT = pathlib.Path('/run/opsdrill-n02')
STATE = ROOT / 'state.json'
IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
MARK = 'opsdrill-N02-drop-8080-v1'
SYSTEMCTL = '/usr/bin/systemctl'
SYSTEMD_RUN = '/usr/bin/systemd-run'
PYTHON = '/usr/bin/python3'
WATCHDOG_SECONDS = 180


class Refused(Exception):
    pass


class EnvironmentErrorN02(Exception):
    pass


def run(*args, capture=False, check=True):
    return subprocess.run(args, text=True, capture_output=capture, check=check, timeout=10)


def ns(*args, capture=True, check=True):
    if args[0] not in NAMES:
        raise Refused('Unknown namespace')
    return run(IP, 'netns', 'exec', *args, capture=capture, check=check)


def namespaces():
    return {line.split()[0] for line in run(IP, 'netns', 'list', capture=True).stdout.splitlines() if line.split()}


def inode(name):
    if name not in NAMES:
        raise Refused('Unknown namespace')
    return pathlib.Path('/run/netns', name).stat().st_ino


def timer_name(rid):
    return 'opsdrill-n02-recover-' + rid + '.timer'


def helper_path(rid):
    return ROOT / ('watchdog-' + rid + '.py')


def secure_source(path):
    path = pathlib.Path(os.path.abspath(path))
    for part in (path, *path.parents):
        st = part.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused('Watchdog source path is not root-controlled')
        if part != path and not stat.S_ISDIR(st.st_mode):
            raise Refused('Watchdog source parent is not a directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_nlink != 1 or st.st_size > 1024 * 1024:
            raise Refused('Unsafe watchdog source')
        with os.fdopen(fd, 'rb') as stream:
            fd = -1
            return stream.read()
    finally:
        if fd != -1: os.close(fd)


def systemd_properties(unit, properties):
    result = run(SYSTEMCTL, 'show', unit, *['--property=' + p for p in properties], capture=True, check=False)
    values = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition('=')
        if not sep or key in values or key not in properties: raise Refused('Invalid watchdog unit properties')
        values[key] = value
    # systemd garbage-collects transient units and omits properties for
    # unknown units. Confirm the special case independently; never invent
    # missing properties for a loaded or otherwise ambiguous unit.
    if result.returncode or set(values) != set(properties):
        probe = run(SYSTEMCTL, 'show', unit, '--property=LoadState', capture=True, check=False)
        if probe.stdout.strip() != 'LoadState=not-found':
            raise Refused('Missing or unreadable watchdog unit properties')
        return {key: 'not-found' if key == 'LoadState' else '' for key in properties}
    if values.get('LoadState') == 'not-found':
        # Other fields can be omitted or change as the unit is collected;
        # confirm its state once more before treating it as absent.
        probe = run(SYSTEMCTL, 'show', unit, '--property=LoadState', capture=True, check=False)
        if probe.stdout.strip() != 'LoadState=not-found':
            raise Refused('Watchdog unit changed during inspection')
        return {key: 'not-found' if key == 'LoadState' else '' for key in properties}
    return values


def helper_verified(state):
    path = helper_path(state['run_id'])
    data = secure_source(path)
    if not state['helper_sha256'] or hashlib.sha256(data).hexdigest() != state['helper_sha256']:
        raise Refused('Watchdog helper identity mismatch')
    return path


def verify_service(state, path, service):
    service_name = state['timer'][:-6] + '.service'
    expected = 'argv[]=' + PYTHON + ' ' + str(path) + ' watchdog ' + state['run_id'] + ' ;'
    if (service['Id'] != service_name or service['LoadState'] != 'loaded' or service['Transient'] != 'yes'
            or service['FragmentPath'] != '/run/systemd/transient/' + service_name or service['User'] != 'root'
            or 'path=' + PYTHON + ' ;' not in service['ExecStart'] or expected not in service['ExecStart']):
        raise Refused('Watchdog service identity mismatch')


def verify_units(state, path):
    timer = systemd_properties(state['timer'], ('Id','LoadState','ActiveState','SubState','Triggers','Transient','FragmentPath'))
    service_name = state['timer'][:-6] + '.service'
    service = systemd_properties(service_name, ('Id','LoadState','ActiveState','Transient','FragmentPath','ExecStart','User'))
    if timer['LoadState'] == 'not-found':
        if service['LoadState'] != 'not-found': verify_service(state, path, service)
        return timer, service
    if (timer['Id'] != state['timer'] or timer['LoadState'] != 'loaded'
            or timer['Triggers'] != service_name or timer['Transient'] != 'yes'
            or timer['FragmentPath'] != '/run/systemd/transient/' + state['timer']):
        raise Refused('Watchdog timer has unexpected identity')
    verify_service(state, path, service)
    return timer, service


def verify_watchdog(state):
    if state['timer'] != timer_name(state['run_id']) or not state['armed_at']:
        raise Refused('Watchdog not recorded')
    path = helper_verified(state)
    timer, service = verify_units(state, path)
    if timer['LoadState'] != 'loaded' or timer['ActiveState'] != 'active' or timer['SubState'] != 'waiting':
        raise Refused('Watchdog timer is not armed')
    if time.monotonic_ns() - state['armed_at'] > (WATCHDOG_SECONDS - 60) * 1_000_000_000:
        raise Refused('Watchdog window is too short for injection')


def stop_owned_watchdog(state):
    if state['timer'] is None:
        if state['helper_sha256'] is not None or state['armed_at'] is not None:
            raise Refused('Incomplete watchdog ownership')
        path = helper_path(state['run_id'])
        if os.path.lexists(path):
            if hashlib.sha256(secure_source(path)).digest() != hashlib.sha256(secure_source(__file__)).digest():
                raise Refused('Unrecorded watchdog helper differs from controller')
            return path
        return None
    if state['timer'] != timer_name(state['run_id']):
        raise Refused('Invalid watchdog identity')
    path = helper_path(state['run_id'])
    if not os.path.lexists(path) and not state['namespaces']:
        timer = systemd_properties(state['timer'], ('LoadState',))
        service = systemd_properties(state['timer'][:-6] + '.service', ('LoadState',))
        if timer['LoadState'] == service['LoadState'] == 'not-found': return None
        raise Refused('Watchdog helper missing while unit exists')
    path = helper_verified(state)
    timer, service = verify_units(state, path)
    if service['LoadState'] != 'not-found' and service['ActiveState'] in ('active', 'activating', 'deactivating', 'reloading'):
        raise Refused('Watchdog service is running; retry reset after it finishes')
    if timer['LoadState'] == 'not-found':
        return path
    run(SYSTEMCTL, 'stop', state['timer'], capture=True)
    # Recheck service after stopping: it may have started during the stop.
    after = systemd_properties(state['timer'][:-6] + '.service', ('Id','LoadState','ActiveState','Transient','FragmentPath','ExecStart','User'))
    if after['LoadState'] != 'not-found':
        verify_service(state, path, after)
        if after['ActiveState'] in ('active', 'activating', 'deactivating', 'reloading'):
            raise Refused('Watchdog service started during reset; retry later')
    return path


def arm_watchdog(state):
    source = secure_source(__file__)
    path = helper_path(state['run_id'])
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(source)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    state['timer'] = timer_name(state['run_id'])
    state['helper_sha256'] = hashlib.sha256(source).hexdigest()
    state['armed_at'] = time.monotonic_ns()
    save(state)
    unit = state['timer'][:-6]
    existing = systemd_properties(state['timer'], ('LoadState',))
    if existing['LoadState'] != 'not-found':
        raise Refused('Watchdog unit already exists')
    run(SYSTEMD_RUN, '--unit=' + unit, '--on-active=' + str(WATCHDOG_SECONDS) + 's', '--timer-property=AccuracySec=1s', '--service-type=exec', '--property=User=root', PYTHON, str(path), 'watchdog', state['run_id'], capture=True)
    verify_watchdog(state)


def watchdog_preflight():
    # Do this before creating namespaces or any other network object.
    secure_source(__file__)
    run(SYSTEMD_RUN, '--version', capture=True)
    run(SYSTEMCTL, 'show', '--property=Version', capture=True)


def save(state):
    tmp = ROOT / 'state.new'
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(state, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE)
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if tmp.exists():
            tmp.unlink()


def load():
    if not os.path.lexists(STATE):
        return None
    try:
        fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise Refused('Unsafe ownership state') from exc
    try:
        import stat
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077 or st.st_nlink != 1 or st.st_size > 4096:
            raise Refused('Unsafe ownership state')
        try: state = json.loads(os.read(fd, 4097))
        except (ValueError, UnicodeError) as exc: raise Refused('Corrupt ownership state') from exc
    finally:
        os.close(fd)
    if not isinstance(state, dict) or set(state) != {'version', 'namespaces', 'run_id', 'baseline', 'injected', 'intent', 'timer', 'helper_sha256', 'armed_at'} or state['version'] != 4 or not isinstance(state['namespaces'], dict) or type(state['intent']) is not bool:
        raise Refused('Invalid ownership state')
    if not isinstance(state['run_id'], str) or not re.fullmatch(r'[0-9a-f]{24}', state['run_id']):
        raise Refused('Invalid run ID')
    for key in ('baseline', 'injected'):
        if state[key] is not None and (not isinstance(state[key], str) or not re.fullmatch(r'[0-9a-f]{64}', state[key])):
            raise Refused('Invalid rule identity')
    if state['timer'] is not None and state['timer'] != timer_name(state['run_id']):
        raise Refused('Invalid watchdog identity')
    if state['helper_sha256'] is not None and (not isinstance(state['helper_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', state['helper_sha256'])):
        raise Refused('Invalid helper identity')
    if state['armed_at'] is not None and (type(state['armed_at']) is not int or state['armed_at'] <= 0):
        raise Refused('Invalid watchdog timestamp')
    if any(k not in NAMES or type(v) is not int or v <= 0 for k, v in state['namespaces'].items()):
        raise Refused('Invalid namespace identity')
    return state


def validate_owned(state, complete=False):
    actual = namespaces()
    recorded = state['namespaces']
    for name in NAMES:
        if name in actual and (name not in recorded or inode(name) != recorded[name]):
            raise Refused('Unowned or replaced namespace: ' + name)
        if name in recorded and name not in actual:
            raise Refused('Recorded namespace missing: ' + name)
    if complete and set(recorded) != set(NAMES):
        raise Refused('Incomplete topology')


def cleanup(state):
    validate_owned(state)
    for name in state['namespaces']:
        pids = run(IP, 'netns', 'pids', name, capture=True).stdout.strip()
        if pids:
            raise Refused('Namespace contains processes; inspect and stop them explicitly: ' + name)
    # Do not disarm the watchdog while the recorded fault remains active.
    # If subsequent cleanup fails, the baseline is already restored.
    if state.get('injected') is not None:
        repair(state)
    helper = stop_owned_watchdog(state)
    for name in reversed(NAMES):
        if name in state['namespaces']:
            # Recheck immediately before destructive operations.
            validate_owned(state)
            if run(IP, 'netns', 'pids', name, capture=True).stdout.strip():
                raise Refused('Namespace acquired processes; refusing deletion: ' + name)
            run(IP, 'netns', 'del', name)
            del state['namespaces'][name]
            save(state)
    if helper is not None:
        if state['timer'] is not None:
            helper_verified(state)
        elif hashlib.sha256(secure_source(helper)).digest() != hashlib.sha256(secure_source(__file__)).digest():
            raise Refused('Unrecorded watchdog helper changed')
        helper.unlink()
    STATE.unlink()


def setup():
    if load() is not None or set(NAMES) & namespaces():
        raise Refused('Existing project state or namespace; inspect before setup')
    state = {'version': 4, 'namespaces': {}, 'run_id': secrets.token_hex(12), 'baseline': None, 'injected': None, 'intent': False, 'timer':None, 'helper_sha256':None, 'armed_at':None}
    save(state)
    try:
        for name in NAMES:
            run(IP, 'netns', 'add', name)
            state['namespaces'][name] = inode(name)
            save(state)
        # Both veth pairs originate inside namespaces, never the host namespace.
        ns('od-client', IP, 'link', 'add', 'veth-c', 'type', 'veth', 'peer', 'name', 'veth-rc')
        ns('od-client', IP, 'link', 'set', 'veth-rc', 'netns', 'od-router')
        ns('od-server', IP, 'link', 'add', 'veth-s', 'type', 'veth', 'peer', 'name', 'veth-rs')
        ns('od-server', IP, 'link', 'set', 'veth-rs', 'netns', 'od-router')
        for name in NAMES:
            ns(name, IP, 'link', 'set', 'lo', 'up')
        for name, dev, address in (('od-client','veth-c','10.203.1.2/24'), ('od-router','veth-rc','10.203.1.1/24'), ('od-router','veth-rs','10.203.2.1/24'), ('od-server','veth-s','10.203.2.2/24')):
            ns(name, IP, 'addr', 'add', address, 'dev', dev)
            ns(name, IP, 'link', 'set', dev, 'up')
        ns('od-client', IP, 'route', 'add', 'default', 'via', '10.203.1.1')
        ns('od-server', IP, 'route', 'add', 'default', 'via', '10.203.2.1')
        ns('od-router', '/usr/sbin/sysctl', '-w', 'net.ipv4.ip_forward=1')
        ns('od-router', NFT, 'add', 'table', 'inet', 'od')
        ns('od-router', NFT, 'add', 'chain', 'inet', 'od', 'forward', '{ type filter hook forward priority 0; policy drop; }')
        ns('od-router', NFT, 'add', 'rule', 'inet', 'od', 'forward', 'ct', 'state', 'established,related', 'accept')
        ns('od-router', NFT, 'add', 'rule', 'inet', 'od', 'forward', 'iifname', '"veth-rc"', 'oifname', '"veth-rs"', 'ip', 'saddr', '10.203.1.2', 'ip', 'daddr', '10.203.2.2', 'tcp', 'dport', '8080', 'accept')
        state['baseline'] = table_digest()
        save(state)
    except Exception:
        try:
            if 'od-router' in state['namespaces'] and not state['baseline']:
                raise Refused('Incomplete router ownership; refusing automatic deletion')
            if state['baseline']:
                check_table(state, 'baseline')
            cleanup(state)
        except Exception as error:
            print('Automatic rollback refused; manual inspection required:', error, file=sys.stderr)
        raise
    return state


def rules():
    result = ns('od-router', NFT, '-j', '-a', 'list', 'chain', 'inet', 'od', 'forward', capture=True)
    obj = json.loads(result.stdout)
    return [x['rule'] for x in obj['nftables'] if 'rule' in x]


def tagged_handles():
    return [r['handle'] for r in rules() if r.get('comment') == MARK]


def table_digest(exclude_fault=False):
    data = json.loads(ns('od-router', NFT, '-j', 'list', 'ruleset', capture=True).stdout)
    tables = [entry['table'] for entry in data['nftables'] if 'table' in entry]
    if len(tables) != 1 or tables[0].get('family') != 'inet' or tables[0].get('name') != 'od':
        raise Refused('Router ruleset is not the exclusively owned inet od table')
    marked = [entry for entry in data['nftables'] if entry.get('rule', {}).get('comment') == MARK]
    if exclude_fault:
        if len(marked) != 1:
            raise Refused('Expected exactly one N02 rule')
        rule = marked[0]['rule']
        expected = [
            {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'veth-rc'}},
            {'match': {'op': '==', 'left': {'meta': {'key': 'oifname'}}, 'right': 'veth-rs'}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '10.203.1.2'}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}}, 'right': '10.203.2.2'}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': 8080}},
            {'drop': None},
        ]
        if rule.get('family') != 'inet' or rule.get('table') != 'od' or rule.get('chain') != 'forward' or rule.get('expr') != expected:
            raise Refused('Fault rule expression differs from expected')
        data['nftables'].remove(marked[0])
    def normalize(value, in_counter=False):
        if isinstance(value, dict):
            return {k: normalize(v, k == 'counter') for k, v in value.items()
                    if k != 'handle' and not (in_counter and k in ('packets', 'bytes'))}
        if isinstance(value, list):
            return [normalize(v, in_counter) for v in value]
        return value
    blob = json.dumps(normalize(data), sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(blob).hexdigest()


def check_table(state, kind):
    if not state[kind] or table_digest() != state[kind]:
        raise Refused('N02 nft table differs from recorded identity')


def inject(state):
    verify_watchdog(state)
    check_table(state, 'baseline')
    if tagged_handles():
        raise Refused('N02 fault rule already exists')
    state['intent'] = True
    save(state)
    verify_watchdog(state)
    ns('od-router', NFT, 'insert', 'rule', 'inet', 'od', 'forward', 'iifname', '"veth-rc"', 'oifname', '"veth-rs"', 'ip', 'saddr', '10.203.1.2', 'ip', 'daddr', '10.203.2.2', 'tcp', 'dport', '8080', 'drop', 'comment', '"' + MARK + '"')
    if table_digest(exclude_fault=True) != state['baseline']:
        raise Refused('Unexpected table changes during injection')
    state['injected'] = table_digest()
    state['intent'] = False
    save(state)


def repair(state):
    handles = tagged_handles()
    if len(handles) > 1 or any(type(h) is not int or h <= 0 for h in handles):
        raise Refused('Ambiguous fault rule; inspect manually')
    if handles:
        check_table(state, 'injected')
        ns('od-router', NFT, 'delete', 'rule', 'inet', 'od', 'forward', 'handle', str(handles[0]))
    check_table(state, 'baseline')
    state['injected'] = None
    save(state)


def recover_intent(state):
    """Reconcile an interrupted injection only when the whole table proves ownership."""
    if not state['intent']:
        raise Refused('No interrupted injection intent')
    if not state['baseline'] or state['injected'] is not None:
        raise Refused('Invalid interrupted injection state')
    handles = tagged_handles()
    if not handles:
        check_table(state, 'baseline')
    else:
        if len(handles) != 1 or type(handles[0]) is not int or handles[0] <= 0:
            raise Refused('Ambiguous fault rule; refusing recovery')
        if table_digest(exclude_fault=True) != state['baseline']:
            raise Refused('Unrelated changes; refusing recovery')
        if tagged_handles() != handles:
            raise Refused('Fault handle changed; refusing recovery')
        ns('od-router', NFT, 'delete', 'rule', 'inet', 'od', 'forward', 'handle', str(handles[0]))
        check_table(state, 'baseline')
    state['intent'] = False
    state['injected'] = None
    save(state)


def watchdog_recover(state, rid, current_file):
    if state is None or state['run_id'] != rid:
        return
    validate_owned(state, complete=True)
    if pathlib.Path(os.path.abspath(current_file)) != helper_path(rid):
        raise Refused('Watchdog must run from its protected helper')
    helper_verified(state)
    if state['intent']: recover_intent(state)
    else: repair(state)
    print('N02 watchdog restored baseline for run ' + rid)


SERVER = r'''import select,socket,time
s=[]
for port in (8080,3306):
 x=socket.socket(); x.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); x.bind(("10.203.2.2",port)); x.listen(4); s.append(x)
print("READY",flush=True)
end=time.monotonic()+15
while time.monotonic()<end:
 ready,_,_=select.select(s,[],[],min(1,max(0,end-time.monotonic())))
 for x in ready:
  c,_=x.accept(); c.settimeout(1)
  if x is s[0]:
   try: c.recv(4096); c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
   except OSError: pass
  c.close()
'''


def process_identity(pid):
    # Linux proc stat field 22, with a command name that may contain spaces.
    stat = pathlib.Path('/proc', str(pid), 'stat').read_text()
    start = int(stat[stat.rfind(')') + 2:].split()[19])
    netns = pathlib.Path('/proc', str(pid), 'ns', 'net').stat().st_ino
    exe = os.readlink('/proc/%d/exe' % pid)
    return start, netns, exe


def stop_owned(proc, identity):
    if proc.poll() is not None:
        return
    if process_identity(proc.pid) != identity:
        raise Refused('Listener identity changed; refusing to signal')
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        if process_identity(proc.pid) != identity:
            raise Refused('Listener identity changed; refusing to kill')
        proc.kill()
        proc.wait(timeout=2)


def check(state):
    fault = bool(tagged_handles())
    check_table(state, 'injected' if fault else 'baseline')
    proc = subprocess.Popen([IP, 'netns', 'exec', 'od-server', '/usr/bin/python3', '-u', '-c', SERVER], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    identity = None
    try:
        ready, _, _ = select.select([proc.stdout], [], [], 3)
        if not ready or proc.stdout.readline().strip() != 'READY':
            raise EnvironmentErrorN02('Temporary listeners did not start')
        candidate = process_identity(proc.pid)
        if candidate[1] != state['namespaces']['od-server'] or not re.search(r'/python3(?:\.\d+)?$', candidate[2]):
            raise Refused('Temporary listener identity mismatch')
        identity = candidate
        ns('od-server', '/usr/bin/python3', '-c', 'import socket; s=socket.create_connection(("10.203.2.2",3306),2); s.close()')
        http = ns('od-client', '/usr/bin/curl', '--fail', '--silent', '--show-error', '--connect-timeout', '2', '--max-time', '3', 'http://10.203.2.2:8080/', capture=True, check=False)
        probe = ns('od-client', '/usr/bin/python3', '-c', 'import socket; socket.create_connection(("10.203.2.2",3306),2)', capture=True, check=False)
        if probe.returncode == 0 or ('TimeoutError' not in probe.stderr and 'timed out' not in probe.stderr):
            raise EnvironmentErrorN02('3306 ACL behavior not established')
        if fault and http.returncode == 28:
            print('N02 fault confirmed: 8080 timed out')
            return 1
        if not fault and http.returncode == 0 and http.stdout == 'OK':
            print('N02 behavior verified')
            return 0
        raise EnvironmentErrorN02('8080 behavior does not match recorded table')
    finally:
        # No signal is sent if identity could not be verified. The helper is
        # bounded by its own deadline; reset refuses while any process remains.
        if identity is not None:
            stop_owned(proc, identity)


def guard():
    if os.geteuid() != 0:
        raise Refused('root required')
    marker = pathlib.Path('/etc/opsdrill-lab')
    try: st = marker.lstat()
    except OSError as exc: raise Refused('Lab marker missing or inaccessible') from exc
    if marker.is_symlink() or not marker.is_file() or st.st_uid != 0 or st.st_mode & 0o022 or marker.read_text().strip() != 'ops-drill-kit':
        raise Refused('Unsafe or invalid lab marker')
    virt = run('/usr/bin/systemd-detect-virt', '--vm', capture=True, check=False)
    if virt.returncode != 0 or virt.stdout.strip() != 'vmware':
        raise Refused('VMware guest required')


def acquire_lock(fcntl_module, timeout=0):
    fd = os.open(ROOT / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_mode & 0o077:
            raise Refused('Unsafe lock')
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl_module.flock(fd, fcntl_module.LOCK_EX | fcntl_module.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise
                time.sleep(min(0.5, remaining))
        return fd
    except Exception:
        os.close(fd)
        raise


def start():
    watchdog_preflight()
    state = setup()
    try:
        arm_watchdog(state)
        inject(state)
    except Exception:
        if not state['intent'] and not state['injected']:
            try:
                check_table(state, 'baseline')
                cleanup(state)
            except Exception as cleanup_error:
                print('Pre-injection cleanup refused:', cleanup_error, file=sys.stderr)
        else:
            print('Injection interrupted; inspect protected state manually', file=sys.stderr)
        raise
    return state


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=('start','inject','repair','recover-intent','check','reset','verify-owner','inspect-clean','watchdog','watchdog-status'))
    p.add_argument('run_id', nargs='?')
    args = p.parse_args()
    guard()
    if args.action in ('start', 'inject', 'inspect-clean'):
        if args.run_id is not None: raise Refused('start does not take a run ID')
    elif not args.run_id or not re.fullmatch(r'[0-9a-f]{24}', args.run_id):
        raise Refused('Expected run ID required')
    import fcntl
    try:
        ROOT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    st = ROOT.lstat()
    if ROOT.is_symlink() or not ROOT.is_dir() or st.st_uid != 0 or st.st_mode & 0o077:
        raise Refused('Unsafe state directory')
    fd = acquire_lock(fcntl, timeout=30 if args.action == 'watchdog' else 0)
    try:
        if args.action == 'inspect-clean':
            if load() is not None or set(NAMES) & namespaces():
                raise Refused('Existing or ambiguous N02 resources')
            print('N02 clean')
        elif args.action in ('start', 'inject'):
            state = start()
            print(json.dumps({'receipt': 'N02_OWNER_V1', 'run_id': state['run_id']}))
        else:
            state = load()
            if args.action == 'watchdog':
                watchdog_recover(state, args.run_id, __file__)
                return
            if state is None:
                if args.action == 'check':
                    print('No active N02 exercise', file=sys.stderr)
                    return 1
                if args.action == 'reset' and not (set(NAMES) & namespaces()):
                    return
                raise Refused('No ownership state')
            if state['run_id'] != args.run_id:
                raise Refused('Run ID mismatch')
            if state['intent'] and args.action not in ('recover-intent','watchdog','watchdog-status'):
                raise Refused('Interrupted injection intent; inspect manually')
            validate_owned(state, complete=args.action != 'reset')
            if args.action == 'reset':
                if 'od-router' in state['namespaces'] and not state['baseline']:
                    raise Refused('Incomplete table ownership; inspect manually')
                if 'od-router' in state['namespaces'] and state['baseline']:
                    if table_digest() not in (state['baseline'], state['injected']):
                        raise Refused('N02 nft table differs from recorded identity')
                cleanup(state)
            elif args.action == 'repair': repair(state)
            elif args.action == 'recover-intent': recover_intent(state)
            elif args.action == 'watchdog-status':
                if state['timer'] != timer_name(state['run_id']): raise Refused('No recorded watchdog')
                for unit in (state['timer'], state['timer'][:-6] + '.service'):
                    values = systemd_properties(unit, ('Id','LoadState','ActiveState','SubState','Result'))
                    print(json.dumps(values, sort_keys=True))
            elif args.action == 'verify-owner':
                if table_digest() not in (state['baseline'], state['injected']):
                    raise Refused('N02 nft table differs from recorded identity')
                print('N02 owner verified')
            else: return check(state)
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        sys.exit(main() or 0)
    except Refused as exc:
        print('N02 refused:', exc, file=sys.stderr)
        sys.exit(3)
    except (EnvironmentErrorN02, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        print('N02 operational failure:', exc, file=sys.stderr)
        sys.exit(2)
