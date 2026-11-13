import os
from pathlib import Path
import pymysql
from fastapi import FastAPI, HTTPException, Request
from app.stage3_api import router as stage3_router, start_stage3_pool, close_stage3_pool, stage3_pool_snapshot
from app.n03_slow import router as n03_slow_router
from app.bounded_pool import BoundedPool, PoolClosed

app = FastAPI(title="OrderGuard", version="0.1.0")
app.include_router(stage3_router)
app.include_router(n03_slow_router)

_pool = None

def _new_db_connection():
    credential = Path(os.environ["CREDENTIALS_DIRECTORY"]) / "mysql-password"
    return pymysql.connect(
        unix_socket="/var/lib/mysql/mysql.sock",
        user="orderguard_app",
        password=credential.read_text(encoding="utf-8").rstrip("\r\n"),
        database="orderguard", charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=3, read_timeout=5, write_timeout=5,
    )

def get_db_connection():
    if _pool is None:
        raise PoolClosed('database pool unavailable')
    return _pool.connection()

@app.on_event('startup')
def start_pools():
    global _pool
    if _pool is not None:
        raise RuntimeError('database pool already started')
    pool = BoundedPool(_new_db_connection, size=4, wait_timeout=1)
    try:
        start_stage3_pool()
    except BaseException:
        pool.close()
        raise
    _pool = pool

@app.on_event('shutdown')
def close_pools():
    global _pool
    pool, _pool = _pool, None
    try:
        if pool is not None:
            pool.close()
    finally:
        close_stage3_pool()

@app.get('/__opsdrill/pool-metrics', include_in_schema=False)
def pool_metrics(request: Request):
    # Lab service binds loopback; deny requests forwarded through Nginx.
    if request.client is None or request.client.host not in ('127.0.0.1', '::1') or 'x-forwarded-for' in request.headers:
        raise HTTPException(status_code=404, detail='Not found')
    pool = _pool
    return {'scope': 'single-process-lab', 'pid': os.getpid(),
            'legacy': pool.snapshot() if pool is not None else None,
            'stage3': stage3_pool_snapshot()}


@app.get("/health")
def health():
    return {"status": "ok", "service": "orderguard-api"}

@app.get("/orders/{order_id}")
def get_order(order_id: int):
    if order_id < 1:
        raise HTTPException(status_code=422, detail="Invalid order ID")
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, merchant_id, amount, status FROM orders WHERE id = %s",
                    (order_id,),
                )
                order = cursor.fetchone()
    except (pymysql.MySQLError, OSError, PoolClosed):
        raise HTTPException(status_code=503, detail="Database unavailable")
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")
    order["amount"] = str(order["amount"])
    return order


@app.get("/ready")
def ready():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
    except (pymysql.MySQLError, OSError, KeyError, UnicodeError, PoolClosed):
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"status": "ready", "database": "ok"}
