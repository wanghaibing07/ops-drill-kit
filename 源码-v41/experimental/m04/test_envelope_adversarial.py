import base64
import unittest
import pitr_audit as a


def good_envelope():
    block1 = base64.b64encode(b'format').decode()
    block2 = base64.b64encode(b'mapupdate').decode()
    return '\n'.join([
        '/*!50530 SET @@SESSION.PSEUDO_SLAVE_MODE=1*/;',
        '/*!50003 SET @OLD_COMPLETION_TYPE=@@COMPLETION_TYPE,COMPLETION_TYPE=0*/;',
        '/*!80019 SET @@SESSION.REQUIRE_ROW_FORMAT=1*/;',
        'DELIMITER /*!*/;',
        "BINLOG '" + block1 + "'/*!*/;",
        '/*!50718 SET TRANSACTION ISOLATION LEVEL READ COMMITTED*//*!*/;',
        '/*!80001 SET @@session.original_commit_timestamp=123*//*!*/;',
        '/*!80014 SET @@session.original_server_version=80413*//*!*/;',
        '/*!80014 SET @@session.immediate_server_version=80413*//*!*/;',
        "SET @@SESSION.GTID_NEXT= 'ANONYMOUS'/*!*/;",
        'SET TIMESTAMP=123/*!*/;',
        'SET @@session.foreign_key_checks=1, @@session.sql_auto_is_null=0, @@session.unique_checks=1, @@session.autocommit=1/*!*/;',
        'SET @@session.sql_mode=1168113696/*!*/;',
        'SET @@session.auto_increment_increment=1, @@session.auto_increment_offset=1/*!*/;',
        '/*!\\C latin1 *//*!*/;',
        'SET @@session.character_set_client=8,@@session.collation_connection=8,@@session.collation_server=255/*!*/;',
        'SET @@session.lc_time_names=0/*!*/;',
        'SET @@session.collation_database=DEFAULT/*!*/;',
        '/*!80011 SET @@session.default_collation_for_utf8mb4=255*//*!*/;',
        'BEGIN', '/*!*/;', "BINLOG '" + block2 + "'/*!*/;", 'COMMIT/*!*/;',
        "SET @@SESSION.GTID_NEXT= 'AUTOMATIC' /* added by mysqlbinlog */ /*!*/;",
        'DELIMITER ;', '/*!50003 SET COMPLETION_TYPE=@OLD_COMPLETION_TYPE*/;',
        '/*!50530 SET @@SESSION.PSEUDO_SLAVE_MODE=0*/;', ''])


class EnvelopeAdversarialTests(unittest.TestCase):
    def test_baseline_envelope_is_accepted(self):
        a.verify_sql_envelope(good_envelope(), b'format', b'map', b'update')

    def test_inserted_sql_and_executable_comments_are_rejected(self):
        sql = good_envelope()
        for hostile in ('DELETE FROM `orderguard_restore_m04`.`orders`/*!*/;',
                        '/*!50000 DROP TABLE `orderguard_restore_m04`.`orders` *//*!*/;',
                        'SET @@session.sql_log_bin=0/*!*/;',
                        'use `mysql`/*!*/;'):
            with self.subTest(statement=hostile):
                with self.assertRaises(a.AuditError):
                    a.verify_sql_envelope(sql.replace('BEGIN\n', hostile + '\nBEGIN\n'), b'format', b'map', b'update')

    def test_extra_or_changed_binlog_block_is_rejected(self):
        sql = good_envelope()
        with self.assertRaises(a.AuditError):
            a.verify_sql_envelope(sql.replace('COMMIT/*!*/;', "BINLOG 'YWJj'/*!*/;\nCOMMIT/*!*/;"),
                                  b'format', b'map', b'update')
        original = base64.b64encode(b'mapupdate').decode()
        changed = base64.b64encode(b'mapdelete').decode()
        with self.assertRaises(a.AuditError):
            a.verify_sql_envelope(sql.replace(original, changed), b'format', b'map', b'update')


if __name__ == '__main__':
    unittest.main()
