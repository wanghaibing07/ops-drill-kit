"""Immutable descriptor used to bind inspected bytes to the replay client."""
from contextlib import contextmanager
import fcntl
import os
import stat
import m04_controller as ctl

MAX_STREAM = 16 * 1024 * 1024

@contextmanager
def sealed_stream(source_fd, auditor):
    """Read bounded regular file once, audit exact bytes, seal and yield descriptor.

    The auditor must validate the full transaction, row images and SQL envelope;
    no production auditor currently satisfies this contract, so this helper is
    intentionally unconnected to the disabled business entrypoints.
    """
    st = os.fstat(source_fd)
    ctl.require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= MAX_STREAM, 'invalid replay stream source')
    os.lseek(source_fd, 0, os.SEEK_SET)
    chunks = []
    remaining = st.st_size
    while remaining:
        chunk = os.read(source_fd, min(remaining, 1024 * 1024))
        ctl.require(bool(chunk), 'truncated replay stream')
        chunks.append(chunk)
        remaining -= len(chunk)
    ctl.require(not os.read(source_fd, 1), 'replay stream grew during read')
    data = b''.join(chunks)
    auditor(data)
    fd = os.memfd_create('m04-audited-replay', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        written = 0
        while written < len(data):
            n = os.write(fd, data[written:])
            ctl.require(n > 0, 'cannot write replay stream')
            written += n
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        ctl.require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals == seals, 'cannot seal replay stream')
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd
    finally:
        os.close(fd)

@contextmanager
def audited_replay_stream(source_fd, binlog, start, stop, end, contract,
                          update_id, old_amount, delete_id, deleted_row):
    import pitr_audit
    def audit(data):
        pitr_audit.audit_replay(binlog, data, start, stop, end, contract,
                                update_id, old_amount, delete_id, deleted_row)
    with sealed_stream(source_fd, audit) as fd:
        yield fd
