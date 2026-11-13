"""Pure identity comparison for a future M04 reset adapter; no system calls.

This comparison does not collect identities, persist records, stop a service,
or make comparison and stop atomic. Those are required of the future adapter.
"""
from dataclasses import dataclass
import re
import uuid


class IdentityRejected(ValueError):
    pass


@dataclass(frozen=True)
class InstanceIdentity:
    run_id: str
    label: str
    boot_id: str
    server_uuid: str
    primary_uuid: str
    unit: str
    invocation_id: str
    pid: int
    process_start_ticks: int
    uid: int
    executable: str
    argv: tuple
    control_group: str
    socket_device: int
    socket_inode: int


def _uuid(value):
    if not isinstance(value, str):
        raise IdentityRejected('invalid UUID')
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise IdentityRejected('invalid UUID') from exc
    if str(parsed) != value or parsed.int == 0:
        raise IdentityRejected('noncanonical or zero UUID')
    return value


def verify_reset_identity(recorded, observed, mysql_uid, mysql_executable, *, synthetic_no_primary=False):
    """Reject absent, malformed, replaced, cross-run or cross-boot instances.

    recorded must come from a protected durable record after independent
    controller verification; observed must be freshly read from systemd, proc,
    socket and isolated MySQL. This does not make either source trustworthy.
    Caller must also perform controller's full active-unit, process, datadir,
    socket-only and MySQL identity checks under the run lock immediately before
    action. A privileged actor can still replace a unit between check and stop.
    """
    import m04_controller as ctl
    if not isinstance(recorded, InstanceIdentity) or not isinstance(observed, InstanceIdentity):
        raise IdentityRejected('identity missing')
    r = recorded
    if (not isinstance(r.run_id, str) or not re.fullmatch(r'[0-9a-f]{16}', r.run_id)
            or r.label not in ('source', 'target')):
        raise IdentityRejected('invalid run identity')
    _uuid(r.boot_id)
    server_uuid = _uuid(r.server_uuid)
    if synthetic_no_primary and r.primary_uuid == '00000000-0000-0000-0000-000000000000':
        # The sentinel means the primary was deliberately not observed.
        primary_uuid = r.primary_uuid
    else:
        primary_uuid = _uuid(r.primary_uuid)
    if server_uuid == primary_uuid:
        raise IdentityRejected('instance equals primary')
    if (r.unit != ctl.unit(r.run_id, r.label)
            or not isinstance(r.invocation_id, str) or not re.fullmatch(r'[0-9a-f]{32}', r.invocation_id)
            or r.invocation_id == '0' * 32
            or not isinstance(r.control_group, str) or not r.control_group.endswith('/' + r.unit)
            or not isinstance(r.argv, tuple) or r.argv != tuple(ctl.command(r.run_id, r.label))
            or not isinstance(mysql_executable, str) or not mysql_executable.startswith('/')
            or r.executable != mysql_executable):
        raise IdentityRejected('unit, executable or command mismatch')
    if (type(mysql_uid) is not int or mysql_uid <= 0 or type(r.uid) is not int or r.uid != mysql_uid
            or any(type(v) is not int or v <= 0 for v in
                   (r.pid, r.process_start_ticks, r.socket_inode))
            or r.pid <= 1 or type(r.socket_device) is not int or r.socket_device < 0):
        raise IdentityRejected('invalid process or socket identity')
    if observed != recorded:
        raise IdentityRejected('live instance differs from protected run record')
