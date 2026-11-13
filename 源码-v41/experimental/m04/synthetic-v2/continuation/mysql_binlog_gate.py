"""Bind the existing event auditor and future mysqlbinlog to one byte stream."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import io


@dataclass(frozen=True)
class BinlogReceipt:
    start: int
    stop: int
    end: int
    length: int
    sha256: str


@contextmanager
def audited_binlog_stream(source_fd, start, stop, end):
    """Yield (sealed fd, exact bytes, receipt) after existing boundary checks.

    Linux-only via the existing sealed_replay helper. Callers must pass this
    fd to mysqlbinlog (including pass_fds), and pass the returned exact bytes
    to pitr_audit.audit_replay. Boundary checks alone do not audit event bodies
    or SQL. Caller must separately establish source identity and provenance.
    """
    import pitr_audit
    import sealed_replay
    result = None

    def audit(data):
        nonlocal result
        pitr_audit.verify_events(io.BytesIO(data), start, stop, end)
        result = (data, BinlogReceipt(start, stop, end, len(data), hashlib.sha256(data).hexdigest()))

    with sealed_replay.sealed_stream(source_fd, audit) as fd:
        if result is None:
            raise RuntimeError('binlog auditor did not run')
        yield fd, result[0], result[1]
