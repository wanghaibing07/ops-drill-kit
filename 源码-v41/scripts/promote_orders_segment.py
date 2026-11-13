#!/usr/bin/env python3
"""Validate and optionally promote one fixed 50,000-row shadow batch."""
import argparse
import csv
import hashlib
import itertools
import os
import re
import stat
import pwd
from pathlib import Path

import pymysql
from pymysql.cursors import SSCursor

DB = 'orderguard_stage3'
BASE = Path('/var/tmp/ops-drill-kit')
SOURCE = BASE / 'orders-500000-reference.tsv'
SOURCE_SHA = '283a3a0453f2d1945ad33e81a0425ee4cf51bc59d8553bb2936901641f66993b'
COLUMNS = 'order_no,merchant_id,user_id,order_status,amount_cents,pay_channel,created_at,updated_at'


def validate_file(path, expected_sha):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != pwd.getpwnam('devops').pw_uid or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise RuntimeError('source file metadata invalid')
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(block)
    if digest.hexdigest() != expected_sha:
        raise RuntimeError('source file checksum mismatch')


def match_file(connection, table, path, limit=None):
    # Identifiers are constants, never caller-provided.
    with connection.cursor(SSCursor) as cursor, path.open(newline='', encoding='utf-8') as f:
        cursor.execute(f'SELECT {COLUMNS} FROM {table} ORDER BY order_no')
        rows = csv.reader(f, delimiter='\t')
        expected = itertools.islice(rows, limit) if limit is not None else rows
        for number, (db_row, file_row) in enumerate(
            itertools.zip_longest(cursor, expected), 1
        ):
            if db_row is None or file_row is None or [str(value) for value in db_row] != file_row:
                raise RuntimeError(f'{table}: data mismatch at row {number}')


def match_reference_segment(reference, batch, start, end):
    with reference.open('rb') as whole, batch.open('rb') as chunk:
        expected = itertools.islice(whole, start - 1, end)
        for number, (left, right) in enumerate(itertools.zip_longest(expected, chunk), start):
            if left != right:
                raise RuntimeError(f'batch differs from reference at row {number}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('start', type=int)
    parser.add_argument('sha256')
    parser.add_argument('--apply', action='store_true', help='commit the validated batch')
    args = parser.parse_args()
    if args.start < 50001 or args.start > 450001 or (args.start - 50001) % 50000 or not re.fullmatch(r'[0-9a-f]{64}', args.sha256):
        parser.error('invalid batch range or SHA256')
    end = args.start + 49999
    table = f'orders_import_{args.start}_{end}'
    batch = BASE / f'orders-{args.start}-{end}.tsv'
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
            cursor.execute(f'LOCK TABLES orders WRITE, {table} READ, merchants READ')
            locked = True
            validate_file(SOURCE, SOURCE_SHA)
            validate_file(batch, args.sha256)
            match_reference_segment(SOURCE, batch, args.start, end)
            cursor.execute('SELECT COUNT(*), COALESCE(SUM(merchant_id=88),0) FROM orders')
            if cursor.fetchone() != (args.start - 1, (args.start - 1) // 20):
                raise RuntimeError('formal table baseline differs from expected count')
            cursor.execute(f'SELECT COUNT(*), COALESCE(SUM(merchant_id=88),0), COUNT(DISTINCT order_no) FROM {table}')
            if cursor.fetchone() != (50000, 2500, 50000):
                raise RuntimeError('batch counts do not match')
            cursor.execute(f'SELECT COUNT(*) FROM {table} WHERE order_no IN (SELECT order_no FROM orders)')
            if cursor.fetchone()[0] != 0:
                raise RuntimeError('batch overlaps existing orders')
            cursor.execute(f'SELECT COUNT(*) FROM {table} WHERE merchant_id NOT IN (SELECT merchant_id FROM merchants)')
            if cursor.fetchone()[0] != 0:
                raise RuntimeError('batch has unknown merchant IDs')
        match_file(connection, 'orders', SOURCE, args.start - 1)
        match_file(connection, table, batch)
        if not args.apply:
            print('PASS: locked tables match both source files; no writes performed')
            connection.rollback()
            return
        with connection.cursor() as cursor:
            cursor.execute(f'INSERT INTO orders ({COLUMNS}) SELECT {COLUMNS} FROM {table} ORDER BY order_no')
            if cursor.rowcount != 50000:
                raise RuntimeError('inserted row count is not 50000')
            cursor.execute('SELECT COUNT(*), COALESCE(SUM(merchant_id=88),0), COUNT(DISTINCT order_no) FROM orders')
            if cursor.fetchone() != (end, end // 20, end):
                raise RuntimeError('post-insert validation failed')
        connection.commit()
        print(f'PASS: committed 50000 rows; total {end}, merchant 88: {end // 20}')
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
