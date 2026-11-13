"""M04 source preparation and controlled fault injection; incomplete drill candidate."""
import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
try:
    import resource
except ImportError:  # Unit tests can run on Windows; production requires Linux.
    resource = None
import pitr_audit
import subprocess
import time
import m04_controller as ctl

BACKUP = Path('/var/backups/opsdrill/M04/full-20261111-01/database.restore.sql.gz')
BACKUP_SHA = '125ce66cae7463cb5a087df6d24218d79aa727652c5f8aaf2d1eb66b99bab80c'
SCHEMA = 'orderguard_restore_m04'
MAX_FILE = 512 * 1024 * 1024

# Fail closed until bounded I/O, least-privilege clients and full binlog body
# validation have been implemented and independently verified.
BUSINESS_ENABLED = False

def require_business_enabled():
    ctl.require(BUSINESS_ENABLED, 'business stages disabled pending safety review')

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def client(rid, label='source'):
    return ['/usr/bin/mysql', '--no-defaults', '--protocol=SOCKET',
            '--socket=' + str(ctl.paths(rid, label)[2]), '--user=root', '--batch', '--skip-column-names']

def ready(rid, state, minimum=30, label='source'):
    now = ctl.require_same_boot(state)
    ctl.require(state.get('phase') == 'READY' and state['deadline_boottime'] - now >= minimum,
                'insufficient instance lifetime')
    ctl.verify(rid, label, state['primary_uuid'], state['uuids'][label])

def query(rid, state, sql):
    ready(rid, state)
    return ctl.sql(rid, 'source', sql)

def phase(directory, state, value):
    state['business_phase'] = value
    ctl.save(directory, state)

def pipeline(producer, consumer, seconds):
    """Connect two processes without shell; kill and reap both on any failure."""
    left = right = None
    try:
        left = subprocess.Popen(producer, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ctl.ENV)
        right = subprocess.Popen(consumer, stdin=left.stdout, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=ctl.ENV)
        left.stdout.close()
        deadline = time.monotonic() + seconds
        rc = right.wait(timeout=max(0.01, deadline - time.monotonic()))
        lc = left.wait(timeout=max(0.01, deadline - time.monotonic()))
        ctl.require(rc == 0 and lc == 0, 'import pipeline failed')
    finally:
        for process in (right, left):
            if process is not None and process.poll() is None:
                process.kill()
        for process in (right, left):
            if process is not None:
                process.wait()

def import_backup(rid, directory, state):
    require_business_enabled()
    ctl.require(state.get('business_phase', 'NEW') == 'NEW', 'business phase is not NEW')
    ready(rid, state, 600)
    state['primary_baseline'] = primary_snapshot(state['primary_uuid'])
    ctl.save(directory, state)
    ctl.require(BACKUP.is_file() and not BACKUP.is_symlink() and digest(BACKUP) == BACKUP_SHA,
                'historical backup mismatch')
    # Test gzip completely before starting any SQL writes.
    with gzip.open(BACKUP, 'rb') as f:
        total = 0
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            total += len(chunk)
            ctl.require(total <= 4 * 1024 * 1024 * 1024, 'uncompressed backup exceeds limit')
    phase(directory, state, 'IMPORTING')
    try:
        query(rid, state, 'CREATE DATABASE orderguard_restore_legacy; CREATE DATABASE orderguard_restore_m04;')
        ready(rid, state, 420)
        # --init-command applies to the same connection as the imported SQL.
        pipeline(['/usr/bin/gzip', '-dc', str(BACKUP)],
                 client(rid) + ['--binary-mode=1', '--init-command=SET SESSION sql_log_bin=0'], 360)
        ctl.require(digest(BACKUP) == BACKUP_SHA, 'historical backup changed')
        ctl.require(query(rid, state, 'SELECT COUNT(*),SUM(merchant_id=88) FROM `' + SCHEMA + '`.orders')
                    == '500000\t25000', 'baseline mismatch')
        state['historical_backup_sha256'] = BACKUP_SHA
        phase(directory, state, 'IMPORTED')
    except BaseException:
        phase(directory, state, 'IMPORT_FAILED')
        raise

def position(rid, state):
    fields = query(rid, state, 'SHOW BINARY LOG STATUS').split('\t')
    ctl.require(len(fields) >= 2 and re.fullmatch(r'pitr-bin\.\d{6}', fields[0]) and fields[1].isdigit(),
                'invalid binary log position')
    return [fields[0], int(fields[1])]

def inject(rid, directory, state):
    require_business_enabled()
    ctl.require(state.get('business_phase') == 'IMPORTED', 'backup import not complete')
    ready(rid, state, 600)
    evidence = directory / 'evidence'
    evidence.mkdir(mode=0o700)
    phase(directory, state, 'BACKING_UP')
    try:
        rows = query(rid, state, 'SELECT id,amount_cents FROM `' + SCHEMA + '`.orders '
                     'WHERE merchant_id=88 AND amount_cents<99900 ORDER BY id LIMIT 2').splitlines()
        ctl.require(len(rows) == 2 and all(re.fullmatch(r'\d+\t\d+', row) for row in rows), 'bad selected rows')
        update_id, amount = map(int, rows[0].split('\t'))
        delete_id = int(rows[1].split('\t')[0])
        ctl.require(update_id > 0 and delete_id > 0 and update_id != delete_id, 'bad order ids')
        query(rid, state, 'FLUSH BINARY LOGS')
        start = position(rid, state)
        dump = evidence / 'full.sql.gz'
        # Compress the complete dump with a strict output size limit and no overwrite.
        dump_cmd = ['/usr/bin/mysqldump', '--no-defaults', '--protocol=SOCKET',
                    '--socket=' + str(ctl.paths(rid, 'source')[2]), '--user=root', '--single-transaction',
                    '--source-data=2', '--set-gtid-purged=OFF', '--databases', SCHEMA]
        ready(rid, state, 420)
        with dump.open('xb') as output:
            def cap():
                resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
            producer = compressor = None
            try:
                producer = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ctl.ENV)
                compressor = subprocess.Popen(['/usr/bin/gzip', '-n'], stdin=producer.stdout, stdout=output,
                                              stderr=subprocess.DEVNULL, env=ctl.ENV, preexec_fn=cap)
                producer.stdout.close()
                deadline = time.monotonic() + 360
                cr = compressor.wait(timeout=max(.01, deadline - time.monotonic()))
                pr = producer.wait(timeout=max(.01, deadline - time.monotonic()))
                ctl.require(cr == 0 and pr == 0, 'full backup failed')
                output.flush()
                os.fsync(output.fileno())
            finally:
                for proc in (compressor, producer):
                    if proc is not None and proc.poll() is None:
                        proc.kill()
                for proc in (compressor, producer):
                    if proc is not None:
                        proc.wait()
        with gzip.open(dump, 'rt', encoding='utf-8') as f:
            header = ''.join(f.readline() for _ in range(45))
        match = re.search(r"SOURCE_LOG_FILE='([^']+)', SOURCE_LOG_POS=(\d+)", header)
        ctl.require(match and [match.group(1), int(match.group(2))] == start and position(rid, state) == start,
                    'backup boundary mismatch')
        state['business'] = {'update_id': update_id, 'delete_id': delete_id, 'start': start,
                             'backup_sha256': digest(dump)}
        phase(directory, state, 'UPDATING')
        query(rid, state, f'UPDATE `{SCHEMA}`.orders SET amount_cents=amount_cents+1 WHERE id={update_id};')
        stop = position(rid, state)
        ctl.require(stop[0] == start[0] and stop[1] > start[1] and
                    query(rid, state, f'SELECT amount_cents FROM `{SCHEMA}`.orders WHERE id={update_id}') == str(amount + 1),
                    'update verification failed')
        state['business']['stop'] = stop
        state['business']['old_amount'] = amount
        deleted = query(rid, state, 'SELECT id,HEX(order_no),merchant_id,user_id,order_status,amount_cents,'
                        'HEX(pay_channel),DATE_FORMAT(created_at,\'%Y-%m-%d %H:%i:%s\'),'
                        'DATE_FORMAT(updated_at,\'%Y-%m-%d %H:%i:%s\') FROM `' + SCHEMA +
                        '`.orders WHERE id=' + str(delete_id)).split('\t')
        ctl.require(len(deleted) == 9 and deleted[0] == str(delete_id), 'cannot capture deleted row')
        state['business']['deleted_row'] = deleted
        state['business']['expected_rows_sha256'] = row_hash(rid, state, 'source', evidence / 'expected-rows.txt')
        state['business']['deleted_row_sha256'] = deleted_hash(rid, state, 'source', delete_id)
        phase(directory, state, 'DELETING')
        query(rid, state, f'DELETE FROM `{SCHEMA}`.orders WHERE id={delete_id};')
        end = position(rid, state)
        ctl.require(end[0] == stop[0] and end[1] > stop[1] and
                    query(rid, state, f'SELECT COUNT(*) FROM `{SCHEMA}`.orders WHERE id={delete_id}') == '0',
                    'delete verification failed')
        state['business']['end'] = end
        phase(directory, state, 'INJECTED')
    except BaseException:
        phase(directory, state, 'INJECT_FAILED')
        raise

ROW_QUERY = ("SELECT id,order_no,merchant_id,user_id,order_status,amount_cents,pay_channel,"
             "DATE_FORMAT(created_at,'%Y-%m-%d %H:%i:%s'),DATE_FORMAT(updated_at,'%Y-%m-%d %H:%i:%s') "
             "FROM orderguard_restore_m04.orders")

def row_hash(rid, state, label, output_path):
    ready(rid, state, 150, label)
    def cap():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    with output_path.open('xb') as output:
        proc = subprocess.run(client(rid, label) + ['-e', ROW_QUERY + ' ORDER BY id'], stdout=output,
                              stderr=subprocess.DEVNULL, env=ctl.ENV, timeout=120, preexec_fn=cap)
        ctl.require(proc.returncode == 0, 'row export failed')
        output.flush()
        os.fsync(output.fileno())
    return digest(output_path)

def deleted_hash(rid, state, label, delete_id):
    ctl.require(type(delete_id) is int and delete_id > 0, 'invalid delete id')
    ready(rid, state, 30, label)
    value = ctl.sql(rid, label, ROW_QUERY + ' WHERE id=' + str(delete_id))
    ctl.require(value and len(value.splitlines()) == 1, 'deleted row missing or ambiguous')
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def execute_capture(args, output, seconds=60):
    def cap():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    with output.open('xb') as f:
        proc = subprocess.run(args, stdout=f, stderr=subprocess.DEVNULL, env=ctl.ENV,
                              timeout=seconds, preexec_fn=cap)
        ctl.require(proc.returncode == 0, 'evidence extraction failed')
        f.flush()
        os.fsync(f.fileno())

def restore(rid, directory, state):
    require_business_enabled()
    ctl.require(state.get('business_phase') == 'INJECTED', 'injection not complete')
    ready(rid, state, 600, 'source')
    ready(rid, state, 600, 'target')
    info = state['business']
    start, stop, end = info['start'], info['stop'], info['end']
    ctl.require(start[0] == stop[0] == end[0] and re.fullmatch(r'pitr-bin\.\d{6}', start[0])
                and type(start[1]) is int and type(stop[1]) is int and type(end[1]) is int
                and 4 <= start[1] < stop[1] < end[1], 'invalid stored boundaries')
    evidence = directory / 'evidence'
    ctl.secure_dir(evidence)
    dump = evidence / 'full.sql.gz'
    ctl.require(dump.is_file() and not dump.is_symlink() and digest(dump) == info['backup_sha256'],
                'backup evidence mismatch')
    ctl.require(digest(evidence / 'expected-rows.txt') == info['expected_rows_sha256'], 'expected row evidence mismatch')
    phase(directory, state, 'EXTRACTING')
    try:
        # Rotate so that the copied closed log is stable and contains the delete.
        query(rid, state, 'FLUSH BINARY LOGS')
        ctl.require(position(rid, state)[0] != start[0], 'log did not rotate')
        source = ctl.paths(rid, 'source')[1] / start[0]
        ctl.require(source.is_file() and not source.is_symlink() and source.stat().st_size <= MAX_FILE,
                    'unsafe or oversized binlog')
        copied = evidence / start[0]
        with source.open('rb') as src, copied.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        with copied.open('rb') as f:
            pitr_audit.verify_events(f, start[1], stop[1], end[1])
        args = ['/usr/bin/mysqlbinlog', '--no-defaults', '--verify-binlog-checksum',
                '--require-row-format', '--start-position=' + str(start[1]), '--stop-position=' + str(stop[1]), str(copied)]
        replay = evidence / 'replay.sql'
        execute_capture(args, replay)
        decoded = evidence / 'update-decoded.txt'
        execute_capture(args[:2] + ['--base64-output=DECODE-ROWS', '--verbose'] + args[2:], decoded)
        delete_decoded = evidence / 'delete-decoded.txt'
        delete_args = args[:2] + ['--base64-output=DECODE-ROWS', '--verbose',
                       '--start-position=' + str(stop[1]), '--stop-position=' + str(end[1]), str(copied)]
        execute_capture(delete_args, delete_decoded)
        pitr_audit.verify_decoded(decoded.read_text(encoding='utf-8'), delete_decoded.read_text(encoding='utf-8'),
                                  info['update_id'], info['delete_id'])
        info['binlog_sha256'] = digest(copied)
        info['replay_sha256'] = digest(replay)
        phase(directory, state, 'RESTORING')
        ready(rid, state, 420, 'target')
        pipeline(['/usr/bin/gzip', '-dc', str(dump)], client(rid, 'target') + ['--binary-mode=1'], 360)
        ready(rid, state, 210, 'target')
        ctl.require(digest(replay) == info['replay_sha256'], 'replay evidence changed')
        import replay_integration
        # Schema provenance must be confirmed on both instances before use.
        contract = verify_schema_contract(rid, state, 'target')
        ctl.require(contract == verify_schema_contract(rid, state, 'source'), 'schema contracts differ')
        replay_integration.audited_restricted_replay(
            rid, directory, state, copied.read_bytes(), replay, start[1], stop[1], end[1], contract,
            info['update_id'], info['old_amount'], info['delete_id'], info['deleted_row'])
        phase(directory, state, 'RESTORED')
    except BaseException:
        phase(directory, state, 'RESTORE_FAILED')
        raise

def check_drill(rid, directory, state):
    require_business_enabled()
    ctl.require(state.get('business_phase') == 'RESTORED', 'restore not complete')
    ready(rid, state, 180, 'target')
    info = state['business']
    evidence = directory / 'evidence'
    ctl.secure_dir(evidence)
    for name, key in [('full.sql.gz', 'backup_sha256'), (info['start'][0], 'binlog_sha256'),
                      ('replay.sql', 'replay_sha256'), ('expected-rows.txt', 'expected_rows_sha256')]:
        path = evidence / name
        ctl.require(path.is_file() and not path.is_symlink() and digest(path) == info[key], 'evidence hash mismatch')
    with (evidence / info['start'][0]).open('rb') as f:
        pitr_audit.verify_events(f, info['start'][1], info['stop'][1], info['end'][1])
    phase(directory, state, 'CHECKING')
    try:
        regenerated = evidence / 'verified-replay.sql'
        execute_capture(['/usr/bin/mysqlbinlog', '--no-defaults', '--verify-binlog-checksum', '--require-row-format',
                         '--start-position=' + str(info['start'][1]), '--stop-position=' + str(info['stop'][1]),
                         str(evidence / info['start'][0])], regenerated)
        ctl.require(digest(regenerated) == info['replay_sha256'], 'replay boundary mismatch')
        target_hash = row_hash(rid, state, 'target', evidence / 'restored-rows.txt')
        ctl.require(target_hash == info['expected_rows_sha256'], 'full order hash mismatch')
        ctl.require(deleted_hash(rid, state, 'target', info['delete_id']) == info['deleted_row_sha256'],
                    'deleted row mismatch')
        phase(directory, state, 'DATA_VERIFIED')
    except BaseException:
        phase(directory, state, 'CHECK_FAILED')
        raise


SCHEMA_QUERY = ("SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COALESCE(CHARACTER_SET_NAME,'-'),"
                "COALESCE(CHARACTER_OCTET_LENGTH,0) FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA='orderguard_restore_m04' AND TABLE_NAME='orders' ORDER BY ORDINAL_POSITION")

def verify_schema_contract(rid, state, label):
    ready(rid, state, 30, label)
    rows = [line.split('\t') for line in ctl.sql(rid, label, SCHEMA_QUERY).splitlines()]
    return pitr_audit.verify_order_columns(rows)


def run_bounded_stage(action, operation, rid, directory, state):
    """Bound the entire CLI stage, including hashes, copies and decompression."""
    import signal
    require_business_enabled()
    starts = {'import': 'NEW', 'inject': 'IMPORTED', 'restore': 'INJECTED', 'check-drill': 'RESTORED',
              'final': 'DATA_VERIFIED'}
    ctl.require(action in starts and state.get('business_phase', 'NEW') == starts[action], 'invalid stage transition')
    armed = False
    previous = None
    try:
        now = ctl.require_same_boot(state)
        remaining = 195 if action == 'final' else state['deadline_boottime'] - now
        ctl.require(remaining > 30, 'insufficient overall runtime')
        ctl.require(hasattr(signal, 'setitimer'), 'stage timer unavailable')
        seconds = min(600, remaining - 15)
        def expired(signum, frame):
            raise TimeoutError('business stage deadline exceeded')
        previous = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, expired)
        armed = True
        signal.setitimer(signal.ITIMER_REAL, seconds)
        operation(rid, directory, state)
    except BaseException:
        # Disarm before persisting to give failure recording a chance to finish.
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
            armed = False
        state['business_phase'] = action.upper().replace('-', '_') + '_FAILED'
        ctl.save(directory, state)
        raise
    finally:
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)


PRIMARY_QUERY = ("SELECT id,HEX(order_no),merchant_id,user_id,order_status,amount_cents,HEX(pay_channel),"
                 "DATE_FORMAT(created_at,'%Y-%m-%d %H:%i:%s'),DATE_FORMAT(updated_at,'%Y-%m-%d %H:%i:%s') "
                 "FROM orderguard_stage3.orders ORDER BY id")

def primary_snapshot(expected_uuid):
    """Read-only ordered digest of primary stage3 orders; never persist rows."""
    base = ['/usr/bin/mysql', '--defaults-extra-file=/etc/opsdrill/mysql-admin.cnf',
            '--batch', '--skip-column-names', '--quick']
    uuid_before = ctl.run(base + ['-e', 'SELECT @@server_uuid'], timeout=15)
    ctl.require(uuid_before.lower() == expected_uuid.lower(), 'primary UUID changed')
    proc = subprocess.Popen(base + ['-e', PRIMARY_QUERY], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=ctl.ENV)
    h = hashlib.sha256()
    total = 0
    try:
        for block in iter(lambda: proc.stdout.read(1024 * 1024), b''):
            total += len(block)
            ctl.require(total <= MAX_FILE, 'primary snapshot exceeds limit')
            h.update(block)
        ctl.require(proc.wait(timeout=30) == 0, 'primary snapshot failed')
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
    uuid_after = ctl.run(base + ['-e', 'SELECT @@server_uuid'], timeout=15)
    ctl.require(uuid_after.lower() == expected_uuid.lower(), 'primary UUID changed during snapshot')
    return {'uuid': uuid_after.lower(), 'orders_sha256': h.hexdigest(), 'bytes': total}

def finalize(rid, directory, state):
    """Only after data verification and stop, compare primary's baseline."""
    require_business_enabled()
    ctl.require(state.get('business_phase') == 'DATA_VERIFIED' and state.get('phase') == 'STOPPED',
                'data verification and stop required')
    ctl.require(not state.get('replay_account'), 'replay account cleanup incomplete')
    ctl.require(isinstance(state.get('primary_baseline'), dict), 'primary baseline missing')
    # Recheck both units and sockets in case something restarted after reset.
    for label in ('source', 'target'):
        for initializing in (True, False):
            name = ctl.init_unit(rid, label) if initializing else ctl.unit(rid, label)
            props = ctl.properties(name)
            ctl.require(ctl.absent(props) or props.get('ActiveState') in ('inactive', 'failed'),
                        'isolated unit still active or unknown')
        ctl.require(not os.path.lexists(ctl.paths(rid, label)[2]), 'isolated socket still exists')
    ctl.require(ctl.run(['/usr/bin/systemctl', 'is-active', 'mysqld'], timeout=15) == 'active',
                'primary service not active')
    phase(directory, state, 'FINALIZING')
    ctl.require(primary_snapshot(state['primary_uuid']) == state['primary_baseline'], 'primary data changed')
    phase(directory, state, 'FINAL_VERIFIED')
