"""Read-only paginated access to the synthetic Stage 3 order dataset."""
import logging
import os
from pathlib import Path

import pymysql
from fastapi import APIRouter, HTTPException, Query
from pymysql.cursors import DictCursor
from app.bounded_pool import BoundedPool, PoolClosed

logger = logging.getLogger(__name__)
router = APIRouter()


_pool = None


def _new_stage3_connection():
    directory = Path(os.environ['CREDENTIALS_DIRECTORY'])
    credential = directory / 'stage3-reader-password'
    return pymysql.connect(
        unix_socket=os.environ['STAGE3_MYSQL_SOCKET'],
        user='orderguard_stage3_reader',
        password=credential.read_text(encoding='utf-8').rstrip('\r\n'),
        database='orderguard_stage3',
        charset='utf8mb4',
        cursorclass=DictCursor,
        connect_timeout=3,
        read_timeout=5,
        write_timeout=5,
        autocommit=False,
    )


def start_stage3_pool():
    global _pool
    if _pool is not None:
        raise RuntimeError('stage3 pool already started')
    _pool = BoundedPool(_new_stage3_connection, size=4, wait_timeout=1)


def close_stage3_pool():
    global _pool
    pool, _pool = _pool, None
    if pool is not None:
        pool.close()


def stage3_pool_snapshot():
    pool = _pool
    return pool.snapshot() if pool is not None else None


def get_stage3_connection():
    if _pool is None:
        raise PoolClosed('stage3 pool unavailable')
    return _pool.connection()


@router.get('/api/v1/orders')
def list_orders(
    merchant_id: int = Query(..., ge=1, le=4294967295),
    page: int = Query(1, ge=1, le=1000000),
    page_size: int = Query(20, ge=1, le=100),
):
    try:
        with get_stage3_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('START TRANSACTION READ ONLY')
                cursor.execute('SELECT COUNT(*) AS total FROM orders WHERE merchant_id=%s', (merchant_id,))
                total = cursor.fetchone()['total']
                cursor.execute(
                    'SELECT order_no,merchant_id,user_id,order_status,amount_cents,'
                    'pay_channel,created_at,updated_at FROM orders WHERE merchant_id=%s '
                    'ORDER BY created_at DESC,id DESC LIMIT %s OFFSET %s',
                    (merchant_id, page_size, (page - 1) * page_size),
                )
                items = cursor.fetchall()
    except (pymysql.MySQLError, OSError, KeyError, UnicodeError, PoolClosed) as exc:
        # Do not log exception text: it may contain connection details.
        logger.error('Stage 3 database unavailable (%s)', type(exc).__name__)
        raise HTTPException(status_code=503, detail='Database unavailable') from None
    return {'merchant_id': merchant_id, 'total': total, 'page': page,
            'page_size': page_size, 'items': items}
