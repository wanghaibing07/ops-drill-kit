"""Small synchronous DB-API connection pool candidate; no database dependency.

The configured limit is per pool, normally one pool per application worker.
The factory must enforce its own connect/read/write timeouts.
"""
from contextlib import contextmanager
import math
import secrets
import threading
import time


class PoolTimeout(TimeoutError):
    pass


class PoolClosed(RuntimeError):
    pass


class BoundedPool:
    def __init__(self, factory, size, wait_timeout):
        if not callable(factory) or type(size) is not int or size < 1:
            raise ValueError('factory and positive integer size required')
        if (isinstance(wait_timeout, bool) or not isinstance(wait_timeout, (int, float))
                or not math.isfinite(wait_timeout) or wait_timeout <= 0):
            raise ValueError('finite positive wait timeout required')
        self._factory = factory
        self._size = size
        self._wait_timeout = wait_timeout
        self._condition = threading.Condition()
        self._idle = []
        self._total = 0  # includes creations, leases, closing and quarantine
        self._quarantined = []  # failed closes keep their slots; never reused
        self._closed = False
        self._generation = secrets.token_hex(16)
        self._errors = {key: 0 for key in ('closed', 'timeout', 'factory', 'ping', 'rollback', 'close', 'borrower')}

    def _count_error(self, name):
        with self._condition:
            self._errors[name] += 1

    def snapshot(self):
        with self._condition:
            return {'generation': self._generation, 'monotonic_ns': time.monotonic_ns(),
                    'capacity': self._size, 'total': self._total, 'idle': len(self._idle),
                    'quarantined': len(self._quarantined), 'closed': self._closed, 'errors': dict(self._errors)}

    def _discard(self, connection):
        try:
            connection.close()
        except BaseException:
            self._count_error('close')
            # If close fails, the server may still count this connection.
            with self._condition:
                self._quarantined.append(connection)
                self._condition.notify_all()
            raise
        with self._condition:
            self._total -= 1
            self._condition.notify_all()

    def _acquire(self):
        deadline = time.monotonic() + self._wait_timeout
        while True:
            with self._condition:
                if self._closed:
                    self._errors['closed'] += 1
                    raise PoolClosed('pool is closed')
                if self._idle:
                    connection = self._idle.pop()
                    creating = False
                elif self._total < self._size:
                    self._total += 1  # reserve before connecting outside the lock
                    connection = None
                    creating = True
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._errors['timeout'] += 1
                        raise PoolTimeout('connection pool wait timed out')
                    self._condition.wait(remaining)
                    continue
            if creating:
                try:
                    connection = self._factory()
                    if connection is None:
                        raise ValueError('connection factory returned None')
                except BaseException:
                    with self._condition:
                        self._errors['factory'] += 1
                        self._total -= 1
                        self._condition.notify_all()
                    raise
            else:
                try:
                    # PyMySQL: do not reconnect behind the pool's accounting.
                    connection.ping(reconnect=False)
                except Exception:
                    self._count_error('ping')
                    self._discard(connection)
                    if time.monotonic() >= deadline:
                        self._count_error('timeout')
                        raise PoolTimeout('connection pool wait timed out')
                    continue
                except BaseException:
                    self._count_error('ping')
                    self._discard(connection)
                    raise
            with self._condition:
                closed = self._closed
            if closed:
                self._count_error('closed')
                self._discard(connection)
                raise PoolClosed('pool closed during acquisition')
            return connection

    @contextmanager
    def connection(self):
        connection = self._acquire()
        try:
            yield connection
        except BaseException as error:
            self._count_error('borrower')
            try:
                self._discard(connection)
            except BaseException as cleanup:
                if hasattr(error, 'add_note'):
                    error.add_note('connection close failed; pool capacity retained: ' + type(cleanup).__name__)
            raise
        else:
            try:
                connection.rollback()  # discard any uncommitted transaction
            except BaseException as error:
                self._count_error('rollback')
                try:
                    self._discard(connection)
                except BaseException as cleanup:
                    if hasattr(error, 'add_note'):
                        error.add_note('connection close failed; pool capacity retained: ' + type(cleanup).__name__)
                raise
            with self._condition:
                if not self._closed:
                    self._idle.append(connection)
                    self._condition.notify()
                    return
            self._discard(connection)

    def close(self):
        """Stop new leases, close idle connections; active leases close on return."""
        with self._condition:
            self._closed = True
            idle, self._idle = self._idle, []
            self._condition.notify_all()
        failures = []
        for connection in idle:
            try:
                self._discard(connection)
            except Exception as exc:
                failures.append(type(exc).__name__)
        if failures:
            raise RuntimeError('some idle connections could not be closed: ' + ', '.join(failures))
