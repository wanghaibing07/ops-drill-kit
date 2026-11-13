#!/usr/bin/env python3
"""Provision a table-scoped reader without exposing its secret on argv or stdout."""
import hashlib
import os
import secrets
import stat
import string
from pathlib import Path
import pymysql

ADMIN = '/etc/opsdrill/mysql-admin.cnf'
OLD = Path('/etc/opsdrill/orderguard-app.password')
NEW = Path('/etc/opsdrill/orderguard-stage3-reader.password')
USER = 'orderguard_stage3_reader'


def digest(path):
    return hashlib.sha256(path.read_bytes()).digest()


def check_denied(cursor, sql):
    try:
        cursor.execute(sql)
    except pymysql.MySQLError as exc:
        if exc.args[0] not in (1142, 1143):
            raise
    else:
        raise RuntimeError('privilege denial check unexpectedly succeeded')


def main():
    if os.geteuid() != 0:
        raise RuntimeError('root required through guard wrapper')
    directory = NEW.parent.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or stat.S_IMODE(directory.st_mode) != 0o700:
        raise RuntimeError('credential directory metadata unexpected')
    old_info = OLD.lstat()
    if not stat.S_ISREG(old_info.st_mode) or old_info.st_uid != 0 or stat.S_IMODE(old_info.st_mode) != 0o600:
        raise RuntimeError('old credential metadata unexpected')
    old_digest = digest(OLD)
    if os.path.lexists(NEW):
        raise RuntimeError('new credential already exists; preserve and inspect')
    admin = pymysql.connect(read_default_file=ADMIN, autocommit=True, connect_timeout=5)
    try:
        with admin.cursor() as c:
            c.execute('SELECT @@GLOBAL.general_log')
            if c.fetchone()[0] != 0:
                raise RuntimeError('general query log is enabled; refuse password-bearing DDL')
            c.execute('SELECT COUNT(*) FROM mysql.user WHERE User=%s AND Host=%s', (USER, 'localhost'))
            if c.fetchone()[0] != 0:
                raise RuntimeError('reader account already exists; preserve and inspect')
            c.execute('SELECT COUNT(*) FROM orderguard_stage3.orders')
            if c.fetchone()[0] != 500000:
                raise RuntimeError('shadow dataset count unexpected')
            c.execute("SHOW GRANTS FOR 'orderguard_app'@'localhost'")
            old_grants = c.fetchall()
        alphabet = string.ascii_letters + string.digits + '_-'
        chars = [secrets.choice(string.ascii_lowercase), secrets.choice(string.ascii_uppercase),
                 secrets.choice(string.digits), secrets.choice('_-')]
        chars.extend(secrets.choice(alphabet) for _ in range(44))
        secrets.SystemRandom().shuffle(chars)
        password = ''.join(chars)
        fd = os.open(NEW, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='ascii') as f:
            f.write(password)
            f.flush()
            os.fsync(f.fileno())
        new_info = NEW.lstat()
        if new_info.st_uid != 0 or new_info.st_gid != 0 or stat.S_IMODE(new_info.st_mode) != 0o600:
            raise RuntimeError('new credential metadata unexpected')
        dir_fd = os.open(NEW.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        with admin.cursor() as c:
            c.execute("CREATE USER 'orderguard_stage3_reader'@'localhost' IDENTIFIED BY %s", (password,))
            c.execute("GRANT SELECT ON orderguard_stage3.orders TO 'orderguard_stage3_reader'@'localhost'")
        reader = pymysql.connect(unix_socket='/var/lib/mysql/mysql.sock', user=USER,
                                 password=password, database='orderguard_stage3',
                                 autocommit=False, connect_timeout=5)
        try:
            with reader.cursor() as c:
                c.execute('SELECT CURRENT_USER(), COUNT(*) FROM orders')
                user, count = c.fetchone()
                if user != USER + '@localhost' or count != 500000:
                    raise RuntimeError('reader identity or count mismatch')
                for sql in ('UPDATE orders SET amount_cents=amount_cents WHERE 1=0',
                            'DELETE FROM orders WHERE 1=0',
                            'INSERT INTO orders (order_no,merchant_id,user_id,order_status,amount_cents,pay_channel,created_at,updated_at) SELECT order_no,merchant_id,user_id,order_status,amount_cents,pay_channel,created_at,updated_at FROM orders WHERE 1=0',
                            'SELECT * FROM merchants LIMIT 0',
                            'SELECT * FROM legacy_merchants LIMIT 0',
                            'SELECT * FROM legacy_orders LIMIT 0',
                            'SELECT * FROM orderguard.orders LIMIT 0'):
                    check_denied(c, sql)
            reader.rollback()
        finally:
            reader.close()
        with admin.cursor() as c:
            c.execute("SHOW GRANTS FOR 'orderguard_app'@'localhost'")
            if c.fetchall() != old_grants or digest(OLD) != old_digest:
                raise RuntimeError('old grants or credential changed')
            c.execute("SHOW GRANTS FOR 'orderguard_stage3_reader'@'localhost'")
            grants = c.fetchall()
            print('PASS: reader authenticated; SELECT succeeded; writes and unrelated tables denied')
            print('Reader grants:', *[row[0] for row in grants], sep='\n')
            print('PASS: previous grants and credential unchanged; new file root:root 0600')
    finally:
        admin.close()


if __name__ == '__main__':
    main()
