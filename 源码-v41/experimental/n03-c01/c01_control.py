#!/usr/bin/env python3
"""C01 controller candidate. Install only after reviewing all N03 entry points."""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys

STORE_PARENT = '/var/lib/opsdrill'
STORE_NAME = 'c01'
N03_PATH = '/usr/local/libexec/opsdrill/n03/n03_502.py'
N03_SHA256 = '8b527cad68557f7294be8580f58923c5e7a1563daf521b44087d19724bed6d5c'
BOOT_PATH = '/proc/sys/kernel/random/boot_id'
RID = re.compile(r'[0-9a-f]{24}\Z')
OWNER = re.compile(r'[0-9a-f]{32}\Z')
BOOT = re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z')

class Refused(Exception):
    pass

def require(ok, message):
    if not ok: raise Refused(message)

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_FIELD')
        result[key] = value
    return result

def parse(data):
    require(len(data) <= 8192, 'RECORD_TOO_LARGE')
    try: return json.loads(data.decode('utf-8'), object_pairs_hook=pairs)
    except (UnicodeError, ValueError): raise Refused('INVALID_JSON')

def validate_receipt(receipt):
    require(type(receipt) is dict and set(receipt) == {'kind', 'owner_id', 'run_id', 'timer'}, 'BAD_RECEIPT')
    rid, owner = receipt.get('run_id'), receipt.get('owner_id')
    require(isinstance(rid, str) and RID.fullmatch(rid) and isinstance(owner, str) and OWNER.fullmatch(owner)
            and receipt['kind'] == 'C01_APP_DOWN_V1'
            and receipt['timer'] == 'opsdrill-n03-recover-' + rid + '.timer', 'BAD_RECEIPT')
    return receipt

def validate_record(record):
    require(type(record) is dict and set(record) == {'version', 'receipt', 'actor', 'boot_id'}
            and type(record['version']) is int and record['version'] == 1
            and record['actor'] in ('user', 'agent', 'unknown')
            and isinstance(record['boot_id'], str) and BOOT.fullmatch(record['boot_id']), 'BAD_RECORD')
    validate_receipt(record['receipt'])
    return record

def safe_directory(fd, exact_mode=None):
    st = os.fstat(fd)
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
            and (exact_mode is None or stat.S_IMODE(st.st_mode) == exact_mode), 'UNSAFE_DIRECTORY')

def open_trusted_directory(path):
    require(path.startswith('/') and all(part not in ('.', '..') for part in path.split('/')), 'BAD_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        safe_directory(fd)
        for part in filter(None, path.split('/')):
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = next_fd
            safe_directory(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise

def secure_read(dfd, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= 8192, 'UNSAFE_RECORD')
        data = os.read(fd, 8193)
        require(len(data) == st.st_size, 'RECORD_CHANGED')
        return data
    finally: os.close(fd)

def write_new(dfd, name, value):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            require(n > 0, 'WRITE_FAILED')
            view = view[n:]
        os.fsync(fd)
    finally: os.close(fd)
    os.fsync(dfd)

class Store:
    @contextlib.contextmanager
    def locked(self):
        parent = open_trusted_directory(STORE_PARENT)
        try:
            try:
                os.mkdir(STORE_NAME, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError: pass
            dfd = os.open(STORE_NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        finally: os.close(parent)
        try:
            safe_directory(dfd, 0o700)
            lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
            try:
                st = os.fstat(lock)
                require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                        and stat.S_IMODE(st.st_mode) == 0o600, 'UNSAFE_LOCK')
                fcntl.flock(lock, fcntl.LOCK_EX)
                yield dfd
            finally: os.close(lock)
        finally: os.close(dfd)

    def current(self, dfd):
        try: cfd = os.open('current', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        except FileNotFoundError: return None
        try:
            safe_directory(cfd, 0o700)
            names = set(os.listdir(cfd))
            require(names in ({'receipt.json'}, {'receipt.json', 'done.json'}), 'INCOMPLETE_STORE')
            record = validate_record(parse(secure_read(cfd, 'receipt.json')))
            done = False
            if 'done.json' in names:
                marker = parse(secure_read(cfd, 'done.json'))
                require(marker == {'run_id': record['receipt']['run_id'], 'result': 'CLEANUP_PASS'}, 'BAD_DONE_MARKER')
                done = True
            return record, done
        finally: os.close(cfd)

    def prepare(self, dfd, record):
        validate_record(record)
        existing = self.current(dfd)
        if existing is not None:
            old, done = existing
            require(done, 'C01_RECEIPT_ALREADY_PRESENT')
            archive = 'done-' + old['receipt']['run_id']
            try: os.stat(archive, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise Refused('ARCHIVE_EXISTS')
            os.rename('current', archive, src_dir_fd=dfd, dst_dir_fd=dfd)
            os.fsync(dfd)
        os.mkdir('current', 0o700, dir_fd=dfd)
        os.fsync(dfd)
        cfd = os.open('current', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            safe_directory(cfd, 0o700)
            write_new(cfd, 'receipt.json', record)
        finally: os.close(cfd)
        os.fsync(dfd)

    def mark_done(self, dfd, record):
        current = self.current(dfd)
        require(current == (record, False), 'RECORD_CHANGED')
        cfd = os.open('current', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            safe_directory(cfd, 0o700)
            write_new(cfd, 'done.json', {'run_id': record['receipt']['run_id'], 'result': 'CLEANUP_PASS'})
        finally: os.close(cfd)
        os.fsync(dfd)

def read_boot():
    with open(BOOT_PATH, encoding='ascii') as f: boot = f.read(64).strip()
    require(BOOT.fullmatch(boot), 'BAD_BOOT_ID')
    return boot

def secure_n03_fd():
    parent, name = N03_PATH.rsplit('/', 1)
    dfd = open_trusted_directory(parent)
    try: fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    finally: os.close(dfd)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                and not st.st_mode & 0o022 and st.st_size <= 131072, 'UNSAFE_N03')
        content = b''
        while len(content) <= 131072:
            part = os.read(fd, min(16384, 131073 - len(content)))
            if not part: break
            content += part
        require(len(content) == st.st_size and hashlib.sha256(content).hexdigest() == N03_SHA256, 'N03_DIGEST_MISMATCH')
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise

class N03Backend:
    def call(self, action, receipt):
        validate_receipt(receipt)
        require(action in ('inject', 'check', 'resolve', 'reset'), 'BAD_ACTION')
        fd = secure_n03_fd()
        try:
            cp = subprocess.run(['/usr/bin/python3', '-I', '-B', '/proc/self/fd/' + str(fd),
                                 'c01-' + action, receipt['run_id'], receipt['owner_id']],
                                pass_fds=(fd,), capture_output=True, timeout=90, check=False)
        finally: os.close(fd)
        # Never infer ownership from a nonzero exit code or malformed output.
        require(cp.returncode in ((0, 1) if action == 'check' else (0,)), 'N03_REFUSED_OR_FAILED')
        out = parse(cp.stdout)
        require(type(out) is dict, 'BAD_N03_OUTPUT')
        if action == 'inject': require(out == receipt, 'BAD_N03_RECEIPT')
        elif action == 'check':
            require((cp.returncode == 1 and out == {'status':'FAULT_PRESENT', 'nginx_status':502}) or
                    (cp.returncode == 0 and out == {'status':'RECOVERED', 'health':200, 'ready':200}), 'BAD_N03_CHECK')
        elif action == 'resolve':
            require(set(out) == {'status','service_action'} and out['status'] == 'MITIGATED'
                    and out['service_action'] in ('STARTED','ALREADY_ACTIVE'), 'BAD_N03_RESOLVE')
        else:
            require(set(out) == {'status','run_id','service_action'} and out['status'] == 'CLEANUP_PASS'
                    and out['run_id'] == receipt['run_id'] and out['service_action'] in ('STARTED','ALREADY_ACTIVE'), 'BAD_N03_RESET')
        return cp.returncode, out

class Controller:
    def __init__(self, store, backend, boot=read_boot):
        self.store, self.backend, self.boot = store, backend, boot

    def execute(self, action, actor, expected=None):
        require(actor in ('user','agent','unknown'), 'BAD_ACTOR')
        require(action in ('start','status','check','resolve','reset'), 'BAD_ACTION')
        require((action in ('start','status') and expected is None) or
                (action in ('check','resolve','reset') and isinstance(expected,str) and RID.fullmatch(expected)), 'EXPECTED_RUN_REQUIRED')
        with self.store.locked() as dfd:
            if action == 'start':
                rid = secrets.token_hex(12)
                receipt = {'kind':'C01_APP_DOWN_V1', 'owner_id':secrets.token_hex(16), 'run_id':rid,
                           'timer':'opsdrill-n03-recover-'+rid+'.timer'}
                record = {'version':1, 'receipt':receipt, 'actor':actor, 'boot_id':self.boot()}
                self.store.prepare(dfd, record)
                self.backend.call('inject', receipt)
                return 0, {'status':'FAULT_CONFIRMED','run_id':rid,'actor':actor,'overall':'INCOMPLETE'}
            current = self.store.current(dfd)
            if action == 'status':
                if current is None: return 0, {'status':'NO_RECEIPT'}
                record, done = current
                return 0, {'status':'CLEANUP_RECORDED' if done else 'RECEIPT_PRESENT_UNVERIFIED',
                           'run_id':record['receipt']['run_id'], 'actor':record['actor'],
                           'same_boot':record['boot_id'] == self.boot()}
            require(current is not None, 'NO_RECEIPT')
            record, done = current
            require(not done, 'RUN_ALREADY_CLEANED')
            require(record['receipt']['run_id'] == expected, 'RUN_ID_MISMATCH')
            require(record['boot_id'] == self.boot(), 'BOOT_CHANGED')
            rc, result = self.backend.call(action, record['receipt'])
            if action == 'reset':
                self.store.mark_done(dfd, record)
                return 0, {'status':'CLEANUP_PASS','run_id':expected}
            if action == 'resolve': return 0, {'status':'MITIGATED','run_id':expected}
            if rc == 1: return 1, {'status':'FAULT_PRESENT','gateway_health':502,'overall':'INCOMPLETE'}
            return 2, {'status':'RECOVERED_PARTIAL','overall':'INCOMPLETE'}

def main(argv):
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(len(argv) in (3, 4), 'USAGE')
    rc, result = Controller(Store(), N03Backend()).execute(argv[1], argv[2], argv[3] if len(argv) == 4 else None)
    print(json.dumps(result, sort_keys=True))
    return rc

if __name__ == '__main__':
    try: sys.exit(main(sys.argv))
    except (Refused, OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status':'FAIL_CLOSED','error':str(exc) if isinstance(exc, Refused) else type(exc).__name__}), file=sys.stderr)
        sys.exit(2)
