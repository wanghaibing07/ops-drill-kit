import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from app.bounded_pool import BoundedPool, PoolClosed, PoolTimeout


class Connection:
    def __init__(self):
        self.closed = False
        self.rollbacks = 0
        self.bad_ping = False
        self.bad_rollback = False
        self.bad_close = False

    def ping(self, reconnect):
        assert reconnect is False
        if self.bad_ping:
            raise OSError('stale')

    def rollback(self):
        self.rollbacks += 1
        if self.bad_rollback:
            raise OSError('rollback failed')

    def close(self):
        if self.bad_close:
            raise OSError('close failed')
        self.closed = True


class PoolTests(unittest.TestCase):
    def test_concurrent_borrowers_and_connecting_reservations_are_bounded(self):
        lock = threading.Lock()
        created, active, high = [], 0, 0
        def factory():
            time.sleep(.01)
            connection = Connection()
            with lock:
                created.append(connection)
            return connection
        pool = BoundedPool(factory, size=3, wait_timeout=2)
        def work(_):
            nonlocal active, high
            with pool.connection():
                with lock:
                    active += 1
                    high = max(high, active)
                time.sleep(.02)
                with lock:
                    active -= 1
        with ThreadPoolExecutor(max_workers=12) as executor:
            list(executor.map(work, range(24)))
        self.assertLessEqual(len(created), 3)
        self.assertLessEqual(high, 3)
        self.assertEqual(sum(conn.rollbacks for conn in created), 24)
        pool.close()
        self.assertTrue(all(conn.closed for conn in created))

    def test_wait_timeout_then_reuse(self):
        pool = BoundedPool(Connection, 1, .05)
        with pool.connection() as original:
            with self.assertRaises(PoolTimeout):
                with pool.connection():
                    pass
        with pool.connection() as reused:
            self.assertIs(original, reused)
        pool.close()

    def test_body_failure_closes_connection_and_frees_slot(self):
        pool = BoundedPool(Connection, 1, .1)
        with self.assertRaisesRegex(ValueError, 'query failed'):
            with pool.connection() as old:
                raise ValueError('query failed')
        self.assertTrue(old.closed)
        with pool.connection() as new:
            self.assertIsNot(old, new)
        pool.close()

    def test_factory_failure_returns_reservation(self):
        attempts = []
        def factory():
            attempts.append(1)
            if len(attempts) == 1:
                raise OSError('connect failed')
            return Connection()
        pool = BoundedPool(factory, 1, .1)
        with self.assertRaises(OSError):
            with pool.connection():
                pass
        with pool.connection():
            pass
        pool.close()

    def test_rollback_or_stale_connection_is_discarded(self):
        pool = BoundedPool(Connection, 1, .2)
        with self.assertRaisesRegex(OSError, 'rollback failed'):
            with pool.connection() as bad:
                bad.bad_rollback = True
        self.assertTrue(bad.closed)
        with pool.connection() as stale:
            pass
        stale.bad_ping = True
        with pool.connection() as fresh:
            self.assertIsNot(stale, fresh)
        self.assertTrue(stale.closed)
        pool.close()

    def test_failed_close_keeps_capacity_and_original_exception(self):
        pool = BoundedPool(Connection, 1, .05)
        with self.assertRaisesRegex(ValueError, 'query failed'):
            with pool.connection() as connection:
                connection.bad_close = True
                raise ValueError('query failed')
        with self.assertRaises(PoolTimeout):
            with pool.connection():
                pass
        self.assertFalse(connection.closed)
        pool.close()

    def test_close_while_connecting_rejects_and_closes_created_connection(self):
        entered, proceed = threading.Event(), threading.Event()
        connection = Connection()
        def factory():
            entered.set()
            if not proceed.wait(2):
                raise RuntimeError('test wait failed')
            return connection
        pool = BoundedPool(factory, 1, 1)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(lambda: pool._acquire())
            self.assertTrue(entered.wait(1))
            pool.close()
            proceed.set()
            with self.assertRaises(PoolClosed):
                future.result(timeout=2)
        self.assertTrue(connection.closed)

    def test_close_wakes_waiter_and_closes_returned_lease(self):
        pool = BoundedPool(Connection, 1, 1)
        entered = threading.Event()
        def waiter():
            entered.set()
            with pool.connection():
                pass
        with pool.connection() as connection:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(waiter)
                self.assertTrue(entered.wait(1))
                pool.close()
                with self.assertRaises(PoolClosed):
                    future.result(timeout=2)
            self.assertFalse(connection.closed)
        self.assertTrue(connection.closed)

    def test_invalid_limits_rejected(self):
        for size, timeout in ((0, 1), (True, 1), (1, 0), (1, float('nan')), (1, float('inf'))):
            with self.assertRaises(ValueError):
                BoundedPool(Connection, size, timeout)


if __name__ == '__main__':
    unittest.main()
