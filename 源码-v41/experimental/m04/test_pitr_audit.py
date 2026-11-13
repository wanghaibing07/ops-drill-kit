import io
import struct
import unittest
import unittest.mock
import zlib
import pitr_audit as a

def make_event(pos, typ, server=211):
    size = 23
    header = struct.pack('<IBIIIH', 0, typ, server, size, pos + size, 0)
    return header + struct.pack('<I', zlib.crc32(header) & 0xffffffff)

def example():
    data = b'\xfe\x62\x69\x6e'
    for typ in [34, 2, 19, 31, 16, 34, 2, 19, 32, 16]:
        data += make_event(len(data), typ)
    return data

class AuditTests(unittest.TestCase):
    def test_exact_transactions(self):
        result = a.verify_events(io.BytesIO(example()), 4, 119, 234)
        self.assertEqual(result['stop'], 119)

    def test_reject_bad_boundaries_and_corruption(self):
        data = example()
        for start, stop, end in [(4, 120, 234), (4, 119, 233), (4, 119, 300)]:
            with self.assertRaises(a.AuditError):
                a.verify_events(io.BytesIO(data), start, stop, end)
        broken = bytearray(data)
        broken[28] ^= 1
        with self.assertRaises(a.AuditError):
            a.verify_events(io.BytesIO(broken), 4, 119, 234)
        with self.assertRaises(a.AuditError):
            a.verify_events(io.BytesIO(data[:-1]), 4, 119, 234)

    def test_decode_rejects_changed_other_column(self):
        def image(first, amount, third='3'):
            vals = [first, '2', third, '4', '5', amount, '7', '8', '9']
            return ''.join(f'###   @{i}={v}\n' for i, v in enumerate(vals, 1))
        update = '### UPDATE `orderguard_restore_m04`.`orders`\n### WHERE\n' + image('10', '8') + '### SET\n' + image('10', '9') + 'Xid ='
        delete = '### DELETE FROM `orderguard_restore_m04`.`orders`\n### WHERE\n' + image('11', '8') + 'Xid ='
        a.verify_decoded(update, delete, 10, 11)
        with self.assertRaises(a.AuditError):
            a.verify_decoded(update.replace('@3=3', '@3=4', 1), delete, 10, 11)

    def test_query_and_table_map_restrict_identity(self):
        query = bytes(8) + bytes([0]) + bytes(4) + b'\x00BEGIN'
        a.query_begin(query)
        with self.assertRaises(a.AuditError):
            a.query_begin(query.replace(b'BEGIN', b'DELETE FROM orders'))
        schema, table = b'orderguard_restore_m04', b'orders'
        mapping = (7).to_bytes(6, 'little') + bytes(2) + bytes([len(schema)]) + schema + b'\x00' + bytes([len(table)]) + table + b'\x00'
        self.assertEqual(a.table_map(mapping), 7)
        a.matching_row_table((7).to_bytes(6, 'little') + bytes(4), 7)
        with self.assertRaises(a.AuditError):
            a.matching_row_table((8).to_bytes(6, 'little') + bytes(4), 7)
        with self.assertRaises(a.AuditError):
            a.table_map(mapping.replace(b'orders', b'otherx'))

    def test_blocks_equal_audited_events_byte_for_byte(self):
        import base64
        enc = lambda x: base64.b64encode(x).decode()
        a.compare_binlog_blocks([enc(b'format'), enc(b'mapupdate')], b'format', b'map', b'update')
        with self.assertRaises(a.AuditError):
            a.compare_binlog_blocks([enc(b'format'), enc(b'mapdelete')], b'format', b'map', b'update')
        with self.assertRaises(a.AuditError):
            a.compare_binlog_blocks([enc(b'format'), '%%%'], b'format', b'map', b'update')

    def test_sql_envelope_rejects_unrecognized_statement(self):
        with self.assertRaises(a.AuditError):
            a.verify_sql_envelope('DELETE FROM orders;', b'format', b'map', b'update')

    def test_duplicate_row_images_are_rejected(self):
        with self.assertRaises(a.AuditError):
            a.verify_decoded('### UPDATE `orderguard_restore_m04`.`orders`\n### WHERE\n### WHERE\nXid =', '', 1, 2)

    def test_binary_one_update_and_malicious_variants(self):
        schema, table = b'orderguard_restore_m04', b'orders'
        head = (7).to_bytes(6, 'little') + bytes(2)
        mapping = head + bytes([len(schema)]) + schema + b'\x00' + bytes([len(table)]) + table + b'\x00' + bytes([9]) + bytes([3]*9) + b'\x00' + b'\x00\x00'
        contract = (tuple([3]*9), tuple([b'']*9), b'\x00\x00')
        def row(amount):
            fields = [42, 2, 3, 4, 5, amount, 7, 8, 9]
            return b'\x00\x00' + b''.join(x.to_bytes(4, 'little') for x in fields)
        body = head + b'\x02\x00' + b'\x09\xff\x01\xff\x01' + row(50) + row(51)
        a.parse_single_update(mapping, body, contract, 42, 50)
        real_bitmap = body[:12] + b'\xff' + body[13:14] + b'\xff' + body[15:]
        a.parse_single_update(mapping + bytes.fromhex('0101f80203fcff00'), real_bitmap, contract, 42, 50)
        with self.assertRaises(a.AuditError):
            a.parse_single_update(mapping + b'\x01\x02', body, contract, 42, 50)
        for bad in (body + row(50) + row(51), body[:-1], body[:11] + b'\x00' + body[12:]):
            with self.assertRaises(a.AuditError):
                a.parse_single_update(mapping, bad, contract, 42, 50)
        with self.assertRaises(a.AuditError):
            a.parse_single_update(mapping, body, contract, 43, 50)
        with self.assertRaises(a.AuditError):
            a.parse_single_update(mapping, body, (tuple([8]*9), contract[1], contract[2]), 42, 50)

    def test_expected_ddl_columns_and_rejection(self):
        self.assertEqual(a.verify_order_columns(a.ORDER_COLUMNS), a.ORDER_BINLOG_CONTRACT)
        changed = list(a.ORDER_COLUMNS)
        changed[5] = ('amount_cents', 'int', 'NO', '-', '0')
        with self.assertRaises(a.AuditError):
            a.verify_order_columns(changed)

    def test_binary_delete_single_exact_row(self):
        schema, table = b'orderguard_restore_m04', b'orders'
        head = (7).to_bytes(6, 'little') + bytes(2)
        mapping = head + bytes([len(schema)]) + schema + b'\x00' + bytes([len(table)]) + table + b'\x00' + bytes([9]) + bytes([3]*9) + b'\x00' + b'\x00\x00'
        contract = (tuple([3]*9), tuple([b'']*9), b'\x00\x00')
        values = [42, 2, 3, 4, 5, 50, 7, 8, 9]
        expected = [x.to_bytes(4, 'little') for x in values]
        body = head + b'\x02\x00' + b'\x09\xff\x01' + b'\x00\x00' + b''.join(expected)
        with __import__('unittest').mock.patch.object(a, 'normalize_order_row', side_effect=lambda row, types, meta: row):
            self.assertEqual(a.parse_single_delete(mapping, body, contract, 42, expected), expected)
        for bad in (body + b'\x00', body[:-1]):
            with self.assertRaises(a.AuditError):
                a.parse_single_delete(mapping, bad, contract, 42, expected)
        with self.assertRaises(a.AuditError):
            a.parse_single_delete(mapping, body, contract, 41, expected)
        with self.assertRaises(a.AuditError):
            a.parse_single_delete(mapping, body, contract, 42, expected[:-1] + [b'bad'])

    def test_order_binary_normalization_matches_select_values(self):
        typ, meta, _ = a.ORDER_BINLOG_CONTRACT
        packed = (((2026 * 13 + 11) << 5 | 12) << 17 | (13 << 12) | (14 << 6) | 15) + 0x8000000000
        row = [(42).to_bytes(8, 'little'), b'\x03abc', (88).to_bytes(4, 'little'),
               (5).to_bytes(4, 'little'), b'\x02', (100).to_bytes(4, 'little'), b'\x01x',
               packed.to_bytes(5, 'big'), packed.to_bytes(5, 'big')]
        self.assertEqual(a.normalize_order_row(row, typ, meta),
                         ['42', '616263', '88', '5', '2', '100', '78',
                          '2026-11-12 13:14:15', '2026-11-12 13:14:15'])

    def test_lab_order_row_rejects_bad_images(self):
        schema, table = b'orderguard_restore_m04', b'orders'
        head = (156).to_bytes(6, 'little') + bytes(2)
        types, metadata, nullable = a.ORDER_BINLOG_CONTRACT
        mapping = (head + bytes([len(schema)]) + schema + b'\x00' + bytes([len(table)]) + table + b'\x00'
                   + bytes([9]) + bytes(types) + bytes([6]) + b''.join(metadata) + nullable
                   + bytes.fromhex('0101f80203fcff00'))
        packed = (((2026 * 13 + 11) << 5 | 12) << 17 | (13 << 12) | (14 << 6) | 15) + 0x8000000000
        vals = [(42).to_bytes(8, 'little'), b'\x03abc', (88).to_bytes(4, 'little'),
                (5).to_bytes(4, 'little'), b'\x02', (100).to_bytes(4, 'little'), b'\x01x',
                packed.to_bytes(5, 'big'), packed.to_bytes(5, 'big')]
        expected = a.normalize_order_row(vals, types, metadata)
        body = head + b'\x02\x00' + b'\x09\xff\xff' + b'\x00\x00' + b''.join(vals)
        self.assertEqual(a.parse_single_delete(mapping, body, a.ORDER_BINLOG_CONTRACT, 42, expected), vals)
        bad_values = [vals.copy() for _ in range(3)]
        bad_values[0][1] = b'\x04abc'
        bad_values[1][7] = b'\xff' * 5
        bad_values[2][2] = (89).to_bytes(4, 'little')
        for values in bad_values:
            broken = head + b'\x02\x00' + b'\x09\xff\xff' + b'\x00\x00' + b''.join(values)
            with self.assertRaises(a.AuditError):
                a.parse_single_delete(mapping, broken, a.ORDER_BINLOG_CONTRACT, 42, expected)
        null_row = head + b'\x02\x00' + b'\x09\xff\xff' + b'\x01\x00' + b''.join(vals)
        with self.assertRaises(a.AuditError):
            a.parse_single_delete(mapping, null_row, a.ORDER_BINLOG_CONTRACT, 42, expected)

    def test_base64_event_encodings_and_tampering(self):
        import base64
        enc = lambda x: base64.b64encode(x).decode('ascii')
        fmt = b'format'
        for size in (3, 4, 5, 85):
            table, row = b'x' * size, b'y' * 148
            a.compare_binlog_blocks([enc(fmt), enc(table + row)], fmt, table, row)
            a.compare_binlog_blocks([enc(fmt), enc(table) + '\n' + enc(row)], fmt, table, row)
            for block in (enc(table) + enc(row + b'z'), enc(table) + enc(row)[:-1],
                          enc(table) + enc(row) + enc(b'bad'), enc(table) + '%' + enc(row)):
                with self.subTest(size=size, block=block):
                    with self.assertRaises(a.AuditError):
                        a.compare_binlog_blocks([enc(fmt), block], fmt, table, row)
        with self.assertRaises(a.AuditError):
            a.compare_binlog_blocks([enc(fmt) + enc(b'x'), enc(b'maprow')], fmt, b'map', b'row')

if __name__ == '__main__':
    unittest.main()
