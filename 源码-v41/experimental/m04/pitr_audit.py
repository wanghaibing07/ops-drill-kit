"""M04 binlog transaction boundary verifier; standalone, no VM side effects."""
import hashlib
import re
import struct
import zlib

class AuditError(ValueError):
    pass

def need(condition, message):
    if not condition:
        raise AuditError(message)

def verify_events(stream, start, stop, end):
    """Verify full event checksums and the exact two expected transaction shapes.

    Positions are event byte offsets, not event ordinal numbers. Reject truncated
    files, malformed positions and additional events inside either transaction.
    """
    need(all(type(x) is int for x in (start, stop, end)) and 4 <= start < stop < end,
         'invalid transaction positions')
    need(stream.read(4) == b'\xfe\x62\x69\x6e', 'invalid binlog magic')
    pos = 4
    selected = []
    while True:
        header = stream.read(19)
        if not header:
            break
        need(len(header) == 19, 'truncated event header')
        _, kind, server, size, next_pos, _ = struct.unpack('<IBIIIH', header)
        need(23 <= size <= 64 * 1024 * 1024 and next_pos == pos + size, 'invalid event bounds')
        body = stream.read(size - 19)
        need(len(body) == size - 19, 'truncated event')
        event = header + body
        need(zlib.crc32(event[:-4]) & 0xffffffff == int.from_bytes(event[-4:], 'little'),
             'event checksum mismatch')
        if start <= pos < end:
            selected.append((pos, next_pos, kind, server))
        pos = next_pos
    before = [x for x in selected if x[0] < stop]
    after = [x for x in selected if x[0] >= stop]
    need([x[2] for x in before] == [34, 2, 19, 31, 16] and
         [x[2] for x in after] == [34, 2, 19, 32, 16] and
         before[0][0] == start and before[-1][1] == stop and
         after[0][0] == stop and after[-1][1] == end and
         all(x[3] == 211 for x in selected), 'unexpected transaction boundaries')
    return {'start': start, 'stop': stop, 'end': end}

def sha256_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda: f.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()

def row_image(text, marker):
    match = re.search(marker + r'\n((?:###   @\d+=.*\n)+)', text)
    need(match is not None, 'missing row image')
    pairs = re.findall(r'^###   @(\d+)=(.*)$', match.group(1), re.M)
    need([int(x[0]) for x in pairs] == list(range(1, 10)), 'unexpected row columns')
    return [x[1] for x in pairs]

def verify_decoded(update, deletion, update_id, delete_id):
    need(type(update_id) is int and type(delete_id) is int and update_id > 0 and delete_id > 0
         and update_id != delete_id, 'invalid order identifiers')
    need(update.count('### UPDATE `orderguard_restore_m04`.`orders`') == 1 and
         '### DELETE ' not in update and update.count('Xid =') == 1, 'unexpected replay transaction')
    need(update.count('### WHERE\n') == 1 and update.count('### SET\n') == 1
         and deletion.count('### WHERE\n') == 1 and '### SET\n' not in deletion,
         'unexpected row image count')
    before = row_image(update, r'### WHERE')
    after = row_image(update, r'### SET')
    need(before[0] == str(update_id) and before[5].isdigit() and after[5] == str(int(before[5]) + 1)
         and all(before[i] == after[i] for i in range(9) if i != 5), 'unexpected update image')
    need(deletion.count('### DELETE FROM `orderguard_restore_m04`.`orders`') == 1
         and '### UPDATE ' not in deletion and deletion.count('Xid =') == 1
         and row_image(deletion, r'### WHERE')[0] == str(delete_id), 'unexpected delete image')

# Metadata checks below intentionally do not claim row-image cardinality; they
# are building blocks for a stricter, currently disabled replay gate.
def query_begin(body):
    need(len(body) >= 13, 'short query event')
    db_len = body[8]
    status_len = int.from_bytes(body[11:13], 'little')
    offset = 13 + status_len
    need(offset + db_len + 1 <= len(body) and body[offset + db_len] == 0, 'invalid query layout')
    db = body[offset:offset + db_len]
    statement = body[offset + db_len + 1:]
    need(db in (b'', b'orderguard_restore_m04') and statement == b'BEGIN', 'query not permitted')

def table_map(body):
    need(len(body) >= 10, 'short table map')
    tid = int.from_bytes(body[:6], 'little')
    length = body[8]
    at = 9
    need(at + length + 2 <= len(body) and body[at + length] == 0, 'invalid schema')
    schema = body[at:at + length]
    at += length + 1
    length = body[at]
    at += 1
    need(at + length + 1 <= len(body) and body[at + length] == 0, 'invalid table')
    table = body[at:at + length]
    need(tid > 0 and schema == b'orderguard_restore_m04' and table == b'orders', 'unexpected table')
    return tid

def matching_row_table(body, expected_id):
    need(len(body) >= 10 and int.from_bytes(body[:6], 'little') == expected_id,
         'row table id mismatch')

def compare_binlog_blocks(blocks, format_event, map_event, update_event):
    import base64
    need(len(blocks) == 2, 'unexpected binlog block count')
    actual = [''.join(block.split()) for block in blocks]
    encode = lambda b: base64.b64encode(b).decode('ascii')
    need(actual[0] == encode(format_event) and
         actual[1] in (encode(map_event + update_event), encode(map_event) + encode(update_event)),
         'binlog output event mismatch')


def verify_sql_envelope(text, format_event, map_event, update_event):
    import stream_envelope
    try:
        blocks = stream_envelope.validate(text, 'orderguard_restore_m04')
    except ValueError as exc:
        raise AuditError('replay SQL envelope rejected') from exc
    compare_binlog_blocks(blocks, format_event, map_event, update_event)

# Binary row-image parser deliberately supports a small audited subset. Unknown
# types, metadata, nullable values and partial row images fail closed.
def length_encoded(data, offset):
    need(offset < len(data), 'missing packed integer')
    lead = data[offset]
    if lead < 251:
        return lead, offset + 1
    widths = {252: 2, 253: 3, 254: 8}
    need(lead in widths and offset + 1 + widths[lead] <= len(data), 'invalid packed integer')
    width = widths[lead]
    value = int.from_bytes(data[offset + 1:offset + 1 + width], 'little')
    need(value >= (251 if width == 2 else 65536 if width == 3 else 16777216), 'noncanonical packed integer')
    return value, offset + 1 + width

def parse_map_contract(body):
    tid = table_map(body)
    offset = 9 + body[8] + 1
    offset += 1 + body[offset] + 1
    count, offset = length_encoded(body, offset)
    need(count == 9 and offset + count <= len(body), 'unexpected column count')
    types = tuple(body[offset:offset + count])
    offset += count
    nmeta, offset = length_encoded(body, offset)
    need(offset + nmeta + (count + 7) // 8 <= len(body), 'truncated column metadata')
    metadata = body[offset:offset + nmeta]
    offset += nmeta
    nullable = body[offset:offset + (count + 7) // 8]
    offset += (count + 7) // 8
    optional = body[offset:]
    # MySQL 8.4 lab MINIMAL row metadata: unsigned numeric columns and
    # utf8mb4 default collation. Unknown/extended layouts fail closed.
    need(optional in (b'', bytes.fromhex('0101f80203fcff00')), 'unsupported optional table metadata')
    values = []
    i = 0
    for typ in types:
        size = 2 if typ == 15 else 1 if typ == 18 else 0
        need(typ in (1, 2, 3, 8, 15, 18) and i + size <= len(metadata), 'unsupported type metadata')
        values.append(metadata[i:i + size])
        i += size
    need(i == len(metadata), 'unused type metadata')
    return tid, types, tuple(values), nullable

def parse_single_update(map_body, row_body, expected_contract, expected_id, expected_amount):
    tid, types, metadata, nullable = parse_map_contract(map_body)
    need((types, metadata, nullable) == expected_contract, 'unrecognized order table contract')
    need(types[0] in (1, 2, 3, 8) and types[5] in (1, 2, 3, 8), 'unsupported id or amount type')
    need(len(row_body) >= 10 and int.from_bytes(row_body[:6], 'little') == tid, 'row table id mismatch')
    extra_len = int.from_bytes(row_body[8:10], 'little')
    need(extra_len >= 2 and 8 + extra_len <= len(row_body), 'invalid row extra data')
    pos = 8 + extra_len
    count, pos = length_encoded(row_body, pos)
    need(count == 9, 'unexpected row column count')
    bitmap_size = (count + 7) // 8
    need(pos + 2 * bitmap_size <= len(row_body), 'missing row bitmaps')
    # All nine columns present; no hidden or partial image.
    def full_bitmap(bitmap):
        return len(bitmap) == 2 and bitmap[0] == 0xff and bitmap[1] & 1 == 1
    need(full_bitmap(row_body[pos:pos + bitmap_size]) and
         full_bitmap(row_body[pos + bitmap_size:pos + 2 * bitmap_size]), 'partial row image')
    pos += 2 * bitmap_size
    before, pos = parse_row_image(row_body, pos, types, metadata, bitmap_size)
    after, pos = parse_row_image(row_body, pos, types, metadata, bitmap_size)
    need(pos == len(row_body), 'multiple rows or trailing row data')
    need(int.from_bytes(before[0], 'little') == expected_id and after[0] == before[0], 'row id mismatch')
    need(int.from_bytes(before[5], 'little') == expected_amount and
         int.from_bytes(after[5], 'little') == expected_amount + 1 and
         all(before[i] == after[i] for i in range(9) if i != 5), 'unexpected binary row update')
    return before, after

def audit_replay(binlog, replay_sql, start, stop, end, contract, update_id, old_amount, delete_id, delete_row):
    """Conservatively bind SQL envelope to the audited single update event.

    The explicit contract must be independently obtained and trusted. This
    The expected deleted binary row must be independently captured and trusted.
    This helper is not yet integrated into a production replay workflow.
    """
    import io
    need(isinstance(binlog, bytes) and 0 < len(binlog) <= 512 * 1024 * 1024, 'invalid binlog input')
    need(isinstance(replay_sql, bytes) and 0 < len(replay_sql) <= 16 * 1024 * 1024, 'invalid replay input')
    verify_events(io.BytesIO(binlog), start, stop, end)
    def event_at(pos):
        need(pos + 19 <= len(binlog), 'missing event header')
        size = int.from_bytes(binlog[pos + 9:pos + 13], 'little')
        need(size >= 23 and pos + size <= len(binlog), 'event outside binlog')
        return binlog[pos:pos + size]
    format_event = event_at(4)
    need(format_event[4] == 15, 'missing format event')
    pos = start
    txn = []
    while pos < stop:
        raw = event_at(pos)
        txn.append(raw)
        pos += len(raw)
    need(pos == stop and [x[4] for x in txn] == [34, 2, 19, 31, 16], 'bad update transaction')
    query_begin(txn[1][19:-4])
    deleted = []
    pos = stop
    while pos < end:
        raw = event_at(pos)
        deleted.append(raw)
        pos += len(raw)
    need(pos == end and [x[4] for x in deleted] == [34, 2, 19, 32, 16], 'bad delete transaction')
    query_begin(deleted[1][19:-4])
    parse_single_delete(deleted[2][19:-4], deleted[3][19:-4], contract, delete_id, delete_row)
    parse_single_update(txn[2][19:-4], txn[3][19:-4], contract, update_id, old_amount)
    try:
        text = replay_sql.decode('ascii')
    except UnicodeDecodeError:
        raise AuditError('invalid replay encoding') from None
    verify_sql_envelope(text, format_event, txn[2], txn[3])


def parse_row_image(row_body, pos, types, metadata, bitmap_size):
    need(pos + bitmap_size <= len(row_body), 'missing null bitmap')
    nulls = row_body[pos:pos + bitmap_size]
    need(nulls == b'\x00\x00', 'null columns not supported')
    pos += bitmap_size
    result = []
    for typ, meta in zip(types, metadata):
        if typ in (1, 2, 3, 8):
            length = {1: 1, 2: 2, 3: 4, 8: 8}[typ]
        elif typ == 15:
            maximum = int.from_bytes(meta, 'little')
            prefix = 1 if maximum <= 255 else 2
            need(pos + prefix <= len(row_body), 'short varchar prefix')
            length = prefix + int.from_bytes(row_body[pos:pos + prefix], 'little')
            need(length - prefix <= maximum, 'varchar exceeds column maximum')
        else:  # DATETIME2
            fsp = meta[0]
            need(fsp <= 6, 'bad datetime precision')
            length = 5 + (fsp + 1) // 2
        need(pos + length <= len(row_body), 'truncated row value')
        result.append(row_body[pos:pos + length])
        pos += length
    return result, pos


def parse_single_delete(map_body, row_body, expected_contract, delete_id, expected_row):
    tid, types, metadata, nullable = parse_map_contract(map_body)
    need((types, metadata, nullable) == expected_contract, 'unrecognized order table contract')
    need(len(row_body) >= 10 and int.from_bytes(row_body[:6], 'little') == tid, 'delete table id mismatch')
    extra_len = int.from_bytes(row_body[8:10], 'little')
    need(extra_len >= 2 and 8 + extra_len <= len(row_body), 'invalid row extra data')
    pos = 8 + extra_len
    count, pos = length_encoded(row_body, pos)
    bitmap = row_body[pos:pos + 2]
    need(count == 9 and len(bitmap) == 2 and bitmap[0] == 0xff and bitmap[1] & 1 == 1, 'partial delete image')
    row, pos = parse_row_image(row_body, pos + 2, types, metadata, 2)
    need(pos == len(row_body), 'multiple deleted rows or trailing data')
    need(types[0] in (1, 2, 3, 8) and int.from_bytes(row[0], 'little') == delete_id, 'delete row id mismatch')
    need(normalize_order_row(row, types, metadata) == expected_row, 'deleted row does not match captured image')
    return row


# Derived from the project DDL, not a statement that the live VM matches it.
ORDER_COLUMNS = (
    ('id', 'bigint unsigned', 'NO', '-', '0'),
    ('order_no', 'varchar(32)', 'NO', 'utf8mb4', '128'),
    ('merchant_id', 'int unsigned', 'NO', '-', '0'),
    ('user_id', 'int unsigned', 'NO', '-', '0'),
    ('order_status', 'tinyint unsigned', 'NO', '-', '0'),
    ('amount_cents', 'int unsigned', 'NO', '-', '0'),
    ('pay_channel', 'varchar(16)', 'NO', 'utf8mb4', '64'),
    ('created_at', 'datetime', 'NO', '-', '0'),
    ('updated_at', 'datetime', 'NO', '-', '0'),
)
ORDER_BINLOG_CONTRACT = ((8, 15, 3, 3, 1, 3, 15, 18, 18),
                         (b'', b'\x80\x00', b'', b'', b'', b'', b'\x40\x00', b'\x00', b'\x00'),
                         b'\x00\x00')

def verify_order_columns(rows):
    """Verify independent information_schema rows; reject all deviations."""
    need(isinstance(rows, (list, tuple)) and tuple(tuple(row) for row in rows) == ORDER_COLUMNS,
         'order schema contract mismatch')
    return ORDER_BINLOG_CONTRACT


def normalize_order_row(row, types, metadata):
    """Normalize exact lab row types to independent SELECT's textual fields."""
    need((types, metadata) == ORDER_BINLOG_CONTRACT[:2] and len(row) == 9, 'unexpected order encoding')
    values = []
    for idx, (value, typ, meta) in enumerate(zip(row, types, metadata)):
        if typ in (1, 3, 8):
            values.append(str(int.from_bytes(value, 'little')))
        elif typ == 15:
            prefix = 1 if int.from_bytes(meta, 'little') <= 255 else 2
            need(len(value) >= prefix and int.from_bytes(value[:prefix], 'little') == len(value) - prefix,
                 'invalid string encoding')
            values.append(value[prefix:].hex().upper())
        elif typ == 18:
            need(meta == b'\x00' and len(value) == 5, 'unexpected datetime encoding')
            packed = int.from_bytes(value, 'big') - 0x8000000000
            need(packed >= 0, 'invalid datetime')
            second = packed & 63
            minute = (packed >> 6) & 63
            hour = (packed >> 12) & 31
            day = (packed >> 17) & 31
            yearmonth = packed >> 22
            year, month = divmod(yearmonth, 13)
            import datetime
            try:
                dt = datetime.datetime(year, month, day, hour, minute, second)
            except ValueError:
                raise AuditError('invalid datetime fields') from None
            values.append(dt.strftime('%Y-%m-%d %H:%M:%S'))
        else:
            raise AuditError('unsupported order type')
    return values
