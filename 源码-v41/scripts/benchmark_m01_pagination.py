#!/usr/bin/env python3
"""Compare equivalent deep pages; cursor discovery is excluded from timings."""
import hashlib
import json
import math
import os
import statistics
import time
from pathlib import Path
import pymysql

PASSWORD = Path('/etc/opsdrill/orderguard-stage3-reader.password')
QUERIES = {
    'offset': 'SELECT * FROM orders ORDER BY id LIMIT 400000,20',
    'deferred': ('SELECT o.* FROM orders AS o JOIN '
                 '(SELECT id FROM orders ORDER BY id LIMIT 400000,20) AS page_ids '
                 'ON page_ids.id=o.id ORDER BY page_ids.id'),
    'keyset': 'SELECT * FROM orders WHERE id > %s ORDER BY id LIMIT 20',
}


def fingerprint(rows):
    canonical = [[str(value) for value in row] for row in rows]
    return hashlib.sha256(json.dumps(canonical, separators=(',', ':')).encode()).hexdigest()


def main():
    if os.geteuid() != 0:
        raise SystemExit('run via the guarded sudo wrapper')
    conn = pymysql.connect(unix_socket='/var/lib/mysql/mysql.sock', user='orderguard_stage3_reader',
                           password=PASSWORD.read_text(encoding='utf-8').rstrip('\r\n'),
                           database='orderguard_stage3', autocommit=False, connect_timeout=5,
                           read_timeout=30)
    try:
        with conn.cursor() as c:
            c.execute('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            c.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
            c.execute('SELECT VERSION(),CURRENT_USER(),CONNECTION_ID(),COUNT(*) FROM orders')
            version, identity, connection_id, total = c.fetchone()
            if identity != 'orderguard_stage3_reader@localhost' or total != 500000:
                raise RuntimeError('unexpected reader identity or dataset size')
            c.execute('SELECT id FROM orders ORDER BY id LIMIT 399999,1')
            cursor_id = c.fetchone()[0]
            c.execute('SELECT COUNT(*) FROM orders WHERE id <= %s', (cursor_id,))
            if c.fetchone()[0] != 400000:
                raise RuntimeError('cursor does not identify the 400000th row')
            params = {'offset': (), 'deferred': (), 'keyset': (cursor_id,)}
            plans = {}
            for name, query in QUERIES.items():
                c.execute('EXPLAIN ANALYZE ' + query, params[name])
                plans[name] = '\n'.join(str(row[0]) for row in c.fetchall())
            durations = {name: [] for name in QUERIES}
            hashes = {name: set() for name in QUERIES}
            names = list(QUERIES)
            for iteration in range(60):
                for name in names[iteration % 3:] + names[:iteration % 3]:
                    started = time.perf_counter_ns()
                    c.execute(QUERIES[name], params[name])
                    rows = c.fetchall()
                    elapsed = (time.perf_counter_ns() - started) / 1_000_000
                    if len(rows) != 20:
                        raise RuntimeError(f'{name}: expected 20 rows')
                    ids = [row[0] for row in rows]
                    if len(set(ids)) != 20 or ids != sorted(ids):
                        raise RuntimeError(f'{name}: IDs not unique and ascending')
                    hashes[name].add(fingerprint(rows))
                    if iteration >= 10:
                        durations[name].append(elapsed)
            fingerprints = {name: next(iter(values)) for name, values in hashes.items() if len(values) == 1}
            if len(fingerprints) != 3 or len(set(fingerprints.values())) != 1:
                raise RuntimeError('pagination results differ or changed during measurement')
            results = {}
            for name, samples in durations.items():
                sorted_samples = sorted(samples)
                results[name] = {'min': min(samples), 'median': statistics.median(samples),
                                 'p95': sorted_samples[math.ceil(.95 * len(samples)) - 1],
                                 'max': max(samples), 'mean': statistics.mean(samples),
                                 'samples_ms': samples, 'result_sha256': fingerprints[name],
                                 'explain_analyze': plans[name], 'query': QUERIES[name]}
            print(json.dumps({'version': version, 'current_user': identity, 'connection_id': connection_id,
                              'transaction': 'REPEATABLE READ, consistent snapshot, READ ONLY', 'dataset_rows': total,
                              'offset': 400000, 'page_size': 20, 'cursor_id': cursor_id,
                              'warmup_runs': 10, 'measured_runs': 50, 'concurrency': 1,
                              'ordering': 'id ASC', 'timings_exclude_cursor_discovery': True,
                              'rotation': 'cyclic interleaving', 'results': results}, indent=2))
    finally:
        conn.rollback()
        conn.close()


if __name__ == '__main__':
    main()
