#!/usr/bin/env python3
"""Copy the legacy demo records into independent tables with transaction checks."""
import os
from pathlib import Path
import pymysql

if os.geteuid() != 0:
    raise SystemExit('run via the guarded sudo wrapper')

conn = pymysql.connect(read_default_file='/etc/opsdrill/mysql-admin.cnf',
                       autocommit=False, connect_timeout=5)
try:
    with conn.cursor() as c:
        c.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='orderguard_stage3' AND table_name IN ('legacy_merchants','legacy_orders')")
        if c.fetchone()[0] != 0:
            raise RuntimeError('archive table exists; preserve and inspect it')
        # DDL commits implicitly: if any statement fails, preserve partial tables.
        schema = Path('/opt/ops-drill-kit/sql/005_legacy_archive_schema.sql').read_text(encoding='utf-8')
        for statement in schema.split(';'):
            if statement.strip():
                c.execute(statement)
        c.execute('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        c.execute('START TRANSACTION')
        c.execute('SELECT id FROM orderguard.merchants FORCE INDEX (PRIMARY) ORDER BY id FOR SHARE')
        if tuple(row[0] for row in c.fetchall()) != (1, 2):
            raise RuntimeError('legacy merchant IDs changed')
        c.execute('SELECT id FROM orderguard.orders FORCE INDEX (PRIMARY) ORDER BY id FOR SHARE')
        if tuple(row[0] for row in c.fetchall()) != (1001, 1002, 1003, 1004, 1005):
            raise RuntimeError('legacy order IDs changed')
        c.execute('SELECT (SELECT COUNT(*) FROM orderguard_stage3.legacy_merchants), (SELECT COUNT(*) FROM orderguard_stage3.legacy_orders)')
        if c.fetchone() != (0, 0):
            raise RuntimeError('archive tables are not empty')
        c.execute('INSERT INTO orderguard_stage3.legacy_merchants (id,name,created_at) SELECT id,name,created_at FROM orderguard.merchants ORDER BY id')
        if c.rowcount != 2:
            raise RuntimeError('merchant copy count mismatch')
        c.execute('INSERT INTO orderguard_stage3.legacy_orders (id,merchant_id,amount,status,created_at) SELECT id,merchant_id,amount,status,created_at FROM orderguard.orders ORDER BY id')
        if c.rowcount != 5:
            raise RuntimeError('order copy count mismatch')
        for columns, source, target in (
            ('id,name,created_at', 'orderguard.merchants', 'orderguard_stage3.legacy_merchants'),
            ('id,merchant_id,amount,status,created_at', 'orderguard.orders', 'orderguard_stage3.legacy_orders'),
        ):
            c.execute(f'SELECT {columns} FROM {source} ORDER BY id')
            original = c.fetchall()
            c.execute(f'SELECT {columns} FROM {target} ORDER BY id')
            if c.fetchall() != original:
                raise RuntimeError(f'archive differs from {source}')
        c.execute('SELECT COUNT(*) FROM orderguard_stage3.legacy_orders o LEFT JOIN orderguard_stage3.legacy_merchants m ON o.merchant_id=m.id WHERE m.id IS NULL')
        if c.fetchone()[0] != 0:
            raise RuntimeError('archive contains orphan orders')
    conn.commit()
    print('PASS: committed 2 merchants and 5 orders; all fields identical, no orphans')
except BaseException:
    conn.rollback()
    raise
finally:
    conn.close()
