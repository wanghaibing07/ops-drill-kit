"""Review-only MySQL dump-coordinate and immutable-byte binding.

Uses the existing sealed_replay helper. This module does not create a dump,
execute SQL, connect to MySQL, or prove that SQL in a dump is safe to import.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import re


MAX_DUMP = 16 * 1024 * 1024  # limited to the small synthetic fixture
MAX_HEADER = 64 * 1024
LOG_NAME = re.compile(r'pitr-bin\.\d{6}\Z', re.ASCII)
COORDINATE = re.compile(
    rb"(?m)^-- CHANGE REPLICATION SOURCE TO SOURCE_LOG_FILE='(pitr-bin\.[0-9]{6})', "
    rb"SOURCE_LOG_POS=([0-9]+);\r?$"
)


class BackupRejected(ValueError):
    pass


@dataclass(frozen=True)
class BackupReceipt:
    log_name: str
    position: int
    length: int
    sha256: str


def _position(value):
    if (not isinstance(value, (tuple, list)) or len(value) != 2
            or not isinstance(value[0], str) or not LOG_NAME.fullmatch(value[0])
            or type(value[1]) is not int or not 4 <= value[1] <= 0xffffffffffffffff):
        raise BackupRejected('invalid source position')
    return value[0], value[1]


def validate_dump_bytes(data, before, after):
    """Check one MySQL 8.4-style source-data comment and quiescent boundaries.

    Callers must obtain before/after from the same verified isolated source and
    prove the dump process succeeded. A matching comment is not a SQL audit,
    schema validation, authentication of provenance, or proof of consistency.
    Unknown formats fail closed. Return a receipt for exactly these bytes.
    """
    before, after = _position(before), _position(after)
    if before != after:
        raise BackupRejected('source position changed during dump')
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_DUMP:
        raise BackupRejected('dump size or type rejected')
    matches = list(COORDINATE.finditer(data))
    if len(matches) != 1 or matches[0].end() > MAX_HEADER:
        raise BackupRejected('missing, duplicated or late dump coordinate')
    # Reject malformed additional coordinates, even in comments or literals.
    if data.count(b'SOURCE_LOG_FILE=') != 1 or data.count(b'SOURCE_LOG_POS=') != 1:
        raise BackupRejected('ambiguous dump coordinates')
    try:
        file_name = matches[0].group(1).decode('ascii')
        digits = matches[0].group(2)
        if len(digits) > 20:
            raise BackupRejected('dump position too long')
        position = int(digits)
    except (UnicodeError, ValueError) as exc:
        raise BackupRejected('invalid dump coordinate') from exc
    if _position((file_name, position)) != before:
        raise BackupRejected('dump coordinate differs from source')
    return BackupReceipt(file_name, position, len(data), hashlib.sha256(data).hexdigest())


@contextmanager
def audited_dump_stream(source_fd, before, after):
    """Yield (sealed fd, receipt) for bytes audited by validate_dump_bytes.

    Requires the existing Linux-only sealed_replay module and its dependencies
    on the Python import path. The caller owns source_fd. Reuse is intentionally
    explicit: this is not wired to the disabled business or probe entrypoints.
    """
    import sealed_replay
    receipt = None

    def audit(data):
        nonlocal receipt
        receipt = validate_dump_bytes(data, before, after)

    with sealed_replay.sealed_stream(source_fd, audit) as fd:
        if receipt is None:
            raise BackupRejected('dump auditor did not run')
        yield fd, receipt
