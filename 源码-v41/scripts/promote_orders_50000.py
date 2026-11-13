#!/usr/bin/env python3
"""Validate and optionally promote the fixed 1001..50000 shadow batch."""
import argparse
import csv
import itertools
import os
from pathlib import Path

import pymysql
from pymysql.cursors import SSCursor

DB = 'orderguard_stage3'
SOURCE = Path('/var/tmp/ops-drill-kit/orders-1000-whole.tsv')
BATCH = Path('/var/tmp/ops-drill-kit/orders-1001-50000.tsv')
COLUMNS = 'order_no,merchant_id,user_id,order_status,amount_cents,pay_channel,created_at,updated_at'


def match_file(connection, table, path):
    # Identifiers are constants, never caller-provided.
    with connection.cursor(SSCursor) as cursor, path.open(newline='', encoding='utf-8') as f:
        cursor.execute(f'SELECT {COLUMNS} FROM {table} ORDER BY order_no')
        for number, (db_row, file_row) in enumerate(
            itertools.zip_longest(cursor, csv.reader(f, delimiter='\t')), 1
        ):
            if db_row is None or file_row is None or [str(value) for value in db_row] != file_row:
                raise RuntimeError(f'{table}: data mismatch at row {number}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='commit the validated batch')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('run through the guarded root wrapper')
    connection = pymysql.connect(read_default_file='/etc/opsdrill/mysql-admin.cnf',
                                 database=DB, autocommit=False, connect_timeout=5)
    locked = False
    try:
        with connection.cursor() as cursor:
            cursor.execute('SET SESSION lock_wait_timeout=10')
            # SET autocommit=0 precedes LOCK TABLES. No START TRANSACTION is used,
            # because it would release explicit table locks in MySQL.
            cursor.execute('SET autocommit=0')
            cursor.execute('LOCK TABLES orders WRITE, orders_import_1001_50000 READ, merchants READ')
            locked = True
            cursor.execute('SELECT COUNT(*), COALESCE(SUM(merchant_id=88),0) FROM orders')
            if cursor.fetchone() != (1000, 50):
                raise RuntimeError('formal table baseline differs from 1000/50')
            cursor.execute('SELECT COUNT(*), COALESCE(SUM(merchant_id=88),0), COUNT(DISTINCT order_no) FROM orders_import_1001_50000')
            if cursor.fetchone() != (49000, 2450, 49000):
                raise RuntimeError('batch counts do not match')
            cursor.execute('SELECT COUNT(*) FROM orders_import_1001_50000 WHERE order_no IN (SELECT order_no FROM orders)')
            if cursor.fetchone()[0] != 0:
                raise RuntimeError('batch overlaps existing orders')
            cursor.execute('SELECT COUNT(*) FROM orders_import_1001_50000 WHERE merchant_id NOT IN (SELECT merchant_id FROM merchants)')
            if cursor.fetchone()[0] != 0:
                raise RuntimeError('batch has unknown merchant IDs')
        match_file(connection, 'orders', SOURCE)
        match_file(connection, 'orders_import_1001_50000', BATCH)
        if not args.apply:
            print('PASS: locked tables match both source files; no writes performed')
            connection.rollback()
            return
        with connection.cursor() as cursor:
            cursor.execute(f'INSERT INTO orders ({COLUMNS}) SELECT {COLUMNS} FROM orders_import_1001_50000 ORDER BY order_no')
            if cursor.rowcount != 49000:
                raise RuntimeError('inserted row count is not 49000')
            cursor.execute('SELECT COUNT(*), COALESCE(SUM(merchant_id=88),0), COUNT(DISTINCT order_no) FROM orders')
            if cursor.fetchone() != (50000, 2500, 50000):
                raise RuntimeError('post-insert validation failed')
        connection.commit()
        print('PASS: committed 49000 rows; total 50000, merchant 88: 2500')
    except BaseException:
        connection.rollback()
        raise
    finally:
        if locked:
            with connection.cursor() as cursor:
                cursor.execute('UNLOCK TABLES')
        connection.close()


if __name__ == '__main__':
    main()
