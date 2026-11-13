#!/usr/bin/env python3
"""Measure the plan's M01 query under a fixed single-connection workload."""
import argparse
import hashlib
import json
import math
import os
import statistics
import time
from pathlib import Path
import pymysql

QUERY = ('SELECT id, order_no, amount_cents, created_at FROM orders '
         'WHERE merchant_id = %s AND order_status = %s AND created_at >= %s '
         'ORDER BY created_at DESC LIMIT 20')
PARAMS = (88, 1, '2026-10-01 00:00:00')
PASSWORD = Path('/etc/opsdrill/orderguard-stage3-reader.password')


def result_digest(rows):
    canonical = sorted((int(row[0]), str(row[1]), int(row[2]), str(row[3])) for row in rows)
    payload = json.dumps(canonical, ensure_ascii=True, separators=(',', ':')).encode()
    return hashlib.sha256(payload).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', default='/var/lib/mysql/mysql.sock')
    parser.add_argument('--warmup', type=int, default=10)
    parser.add_argument('--runs', type=int, default=50)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run via guarded sudo wrapper')
    if args.warmup < 0 or not 1 <= args.runs <= 1000:
        parser.error('invalid run count')
    connection = pymysql.connect(unix_socket=args.socket, user='orderguard_stage3_reader',
                                 password=PASSWORD.read_text(encoding='utf-8').rstrip('\r\n'),
                                 database='orderguard_stage3', autocommit=True,
                                 connect_timeout=5, read_timeout=30)
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT VERSION(), CURRENT_USER(), @@socket, @@innodb_buffer_pool_size')
            version, current_user, actual_socket, buffer_pool = cursor.fetchone()
            if current_user != 'orderguard_stage3_reader@localhost' or actual_socket != args.socket:
                raise RuntimeError('unexpected identity or socket')
            cursor.execute('SELECT COUNT(*) FROM orders')
            total = cursor.fetchone()[0]
            if total != 500000:
                raise RuntimeError('dataset size changed')
            cursor.execute('SELECT COUNT(*) FROM orders WHERE merchant_id=%s AND order_status=%s AND created_at >= %s', PARAMS)
            matching = cursor.fetchone()[0]
            cursor.execute('SHOW INDEX FROM orders')
            indexes = [list(row) for row in cursor.fetchall()]
            cursor.execute("SELECT data_length,index_length FROM information_schema.tables WHERE table_schema='orderguard_stage3' AND table_name='orders'")
            size = cursor.fetchone()
            cursor.execute('EXPLAIN FORMAT=JSON ' + QUERY, PARAMS)
            explain_json = json.loads(cursor.fetchone()[0])
            cursor.execute('EXPLAIN ANALYZE ' + QUERY, PARAMS)
            explain_analyze = '\n'.join(str(row[0]) for row in cursor.fetchall())
            for _ in range(args.warmup):
                cursor.execute(QUERY, PARAMS)
                cursor.fetchall()
            durations = []
            fingerprints = set()
            returned = None
            for _ in range(args.runs):
                start = time.perf_counter_ns()
                cursor.execute(QUERY, PARAMS)
                rows = cursor.fetchall()
                durations.append((time.perf_counter_ns() - start) / 1_000_000)
                returned = len(rows)
                fingerprints.add(result_digest(rows))
            if len(fingerprints) != 1:
                raise RuntimeError('query results varied; inspect timestamp ties before comparison')
            ordered = sorted(durations)
            result = {'version': version, 'current_user': current_user, 'socket': actual_socket,
                      'buffer_pool_bytes': buffer_pool, 'dataset_rows': total,
                      'matching_rows': matching, 'returned_rows': returned,
                      'query': QUERY, 'parameters': list(PARAMS), 'warmup_runs': args.warmup,
                      'measured_runs': args.runs, 'concurrency': 1,
                      'latency_ms': {'min': min(durations), 'median': statistics.median(durations),
                                     'p95': ordered[math.ceil(.95 * len(ordered)) - 1],
                                     'max': max(durations), 'mean': statistics.mean(durations),
                                     'samples': durations},
                      'result_sha256': next(iter(fingerprints)),
                      'data_length_bytes': size[0], 'index_length_bytes': size[1],
                      'indexes': indexes, 'explain_json': explain_json,
                      'explain_analyze': explain_analyze}
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    finally:
        connection.close()


if __name__ == '__main__':
    main()
