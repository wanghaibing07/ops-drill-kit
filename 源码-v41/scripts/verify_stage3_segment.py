#!/usr/bin/env python3
"""Independently verify a promoted prefix against the canonical synthetic TSV."""
import csv
import itertools
import sys
from pathlib import Path
import pymysql
from pymysql.cursors import SSCursor

end = int(sys.argv[1])
if end not in range(100000, 500001, 50000):
    raise SystemExit('invalid end')
conn = pymysql.connect(read_default_file='/etc/opsdrill/mysql-admin.cnf',
                       database='orderguard_stage3', autocommit=True, connect_timeout=5)
try:
    with conn.cursor() as c:
        c.execute('SELECT COUNT(*), COALESCE(SUM(merchant_id=88),0), COUNT(DISTINCT order_no), MIN(order_no), MAX(order_no) FROM orders')
        result = c.fetchone()
        if result != (end, end // 20, end, 'OG000000000001', f'OG{end:012d}'):
            raise RuntimeError(f'counts or range mismatch: {result}')
        c.execute('SELECT COUNT(*) FROM orders LEFT JOIN merchants ON orders.merchant_id=merchants.merchant_id WHERE merchants.merchant_id IS NULL')
        if c.fetchone()[0] != 0:
            raise RuntimeError('orphan orders found')
        c.execute('SELECT COUNT(*) FROM orderguard.orders')
        if c.fetchone()[0] != 5:
            raise RuntimeError('old database baseline changed')
        c.execute('SELECT @@GLOBAL.local_infile')
        if c.fetchone()[0] != 0:
            raise RuntimeError('local_infile is not OFF')
    reference = Path('/var/tmp/ops-drill-kit/orders-500000-reference.tsv')
    with conn.cursor(SSCursor) as c, reference.open(newline='', encoding='utf-8') as f:
        c.execute('SELECT order_no,merchant_id,user_id,order_status,amount_cents,pay_channel,created_at,updated_at FROM orders ORDER BY order_no')
        expected = itertools.islice(csv.reader(f, delimiter='\t'), end)
        for i, (row, expected_row) in enumerate(itertools.zip_longest(c, expected), 1):
            if row is None or expected_row is None or [str(value) for value in row] != expected_row:
                raise RuntimeError(f'full prefix differs at row {i}')
    print(f'PASS independent verification: {end} rows, {end // 20} merchant 88, exact prefix, no orphans, old=5, local_infile=OFF', flush=True)
finally:
    conn.close()
