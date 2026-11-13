"""Checks for the existing probe's fixed synthetic nine-column MySQL fixture.

No SQL or I/O. The caller must query independently through verified sockets.
"""
from dataclasses import dataclass


class FixtureRejected(ValueError):
    pass


@dataclass(frozen=True)
class FixtureEvidence:
    before_delete: tuple
    deleted_row: tuple


def _rows(rows):
    if not isinstance(rows, (list, tuple)):
        raise FixtureRejected('expected rows')
    result = []
    for row in rows:
        if not isinstance(row, (list, tuple)) or len(row) != 9 or not all(type(v) is str for v in row):
            raise FixtureRejected('malformed row')
        result.append(tuple(row))
    if len(result) != len({row[0] for row in result}):
        raise FixtureRejected('duplicate row id')
    return tuple(sorted(result, key=lambda row: row[0]))


def capture_fixture(baseline_rows, before_delete_rows):
    """Compare independently queried rows with vm_replay_probe's fixture."""
    import vm_replay_probe as probe
    time = '2026-01-02 03:04:05'
    first = (str(probe.ID_UPDATE), '6D30342D73796E7468657469632D61', '88', '7', '1', '100',
             '74657374', time, time)
    deleted = tuple(probe.DELETED_ROW)
    if _rows(baseline_rows) != _rows((first, deleted)):
        raise FixtureRejected('unexpected initial fixture')
    changed = first[:5] + ('101',) + first[6:]
    expected = _rows((changed, deleted))
    if _rows(before_delete_rows) != expected:
        raise FixtureRejected('update or pre-delete image mismatch')
    return FixtureEvidence(expected, deleted)


def verify_fault(evidence, fault_rows):
    if not isinstance(evidence, FixtureEvidence):
        raise FixtureRejected('missing pre-delete evidence')
    expected = tuple(row for row in evidence.before_delete if row != evidence.deleted_row)
    if len(expected) != 1 or _rows(fault_rows) != expected:
        raise FixtureRejected('delete fault not observed exactly')


def verify_restored(evidence, restored_rows):
    if not isinstance(evidence, FixtureEvidence) or _rows(restored_rows) != evidence.before_delete:
        raise FixtureRejected('restored full fixture differs from pre-delete image')
