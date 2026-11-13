"""Bounded, no-LOCAL-INFILE row conversion for an isolated baseline experiment.

This module does not connect to MySQL or create databases.  The caller must
authenticate the instance and its ownership before submitting SQL generated here.
"""
from datetime import datetime
import hashlib
import re

_NUMBER = re.compile(r'(?:0|[1-9][0-9]*)\Z')
_TIME = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\Z')
_CHANNEL = {'card', 'wallet', 'bank'}
_PREFIX = ('INSERT INTO orderguard_stage3.orders '
           '(order_no,merchant_id,user_id,order_status,amount_cents,pay_channel,created_at,updated_at) VALUES\n')


def parse_batch(data, start, end, expected_sha256):
    """Validate one exact source snapshot and return safely encoded SQL rows."""
    if (not isinstance(data, bytes) or not 1 <= start <= end <= 500000
            or end - start + 1 > 50000 or len(data) > 8 * 1024 * 1024
            or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256)
            or hashlib.sha256(data).hexdigest() != expected_sha256):
        raise ValueError('batch identity mismatch')
    try:
        lines = data.decode('ascii').splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise ValueError('non-ASCII data') from exc
    if len(lines) != end-start+1:
        raise ValueError('batch row count mismatch')
    result = []
    for number, line in enumerate(lines, start):
        if not line.endswith('\n') or '\r' in line:
            raise ValueError('invalid line ending')
        fields = line[:-1].split('\t')
        if len(fields) != 8 or fields[0] != f'OG{number:012d}':
            raise ValueError('invalid order sequence')
        if any(not _NUMBER.fullmatch(value) for value in fields[1:5]):
            raise ValueError('invalid numeric field')
        merchant, user, status, amount = map(int, fields[1:5])
        if not (1 <= merchant <= 500 and 1 <= user <= 50000 and 0 <= status <= 4
                and 100 <= amount <= 99900 and (merchant == 88) == (number % 20 == 0)
                and fields[5] in _CHANNEL):
            raise ValueError('invalid order values')
        if any(not _TIME.fullmatch(value) for value in fields[6:]):
            raise ValueError('invalid timestamp format')
        try:
            created, updated = (datetime.strptime(value, '%Y-%m-%d %H:%M:%S') for value in fields[6:])
        except ValueError as exc:
            raise ValueError('invalid timestamp') from exc
        if updated < created:
            raise ValueError('timestamps out of order')
        # All string fields have been constrained to fixed ASCII alphabets.
        result.append(f"('{fields[0]}',{merchant},{user},{status},{amount},'{fields[5]}','{fields[6]}','{fields[7]}')")
    return result


def statements(rows, per_statement=500):
    if not isinstance(rows, list) or not rows or not 1 <= per_statement <= 500:
        raise ValueError('invalid SQL batch')
    for offset in range(0, len(rows), per_statement):
        yield _PREFIX + ',\n'.join(rows[offset:offset+per_statement]) + ';\n'
