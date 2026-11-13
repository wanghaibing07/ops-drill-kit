"""Strict mysqlbinlog 8.4 envelope allowlist for an offline lab sample."""
import re

PATTERNS = [
    r'/\*!50530 SET @@SESSION\.PSEUDO_SLAVE_MODE=[01]\*/;',
    r'/\*!50003 SET @OLD_COMPLETION_TYPE=@@COMPLETION_TYPE,COMPLETION_TYPE=0\*/;',
    r'/\*!80019 SET @@SESSION\.REQUIRE_ROW_FORMAT=1\*/;',
    r'DELIMITER /\*!\*/;', r'DELIMITER ;',
    r'/\*!50718 SET TRANSACTION ISOLATION LEVEL READ COMMITTED\*//\*!\*/;',
    r'/\*!80001 SET @@session\.original_commit_timestamp=\d+\*//\*!\*/;',
    r'/\*!80014 SET @@session\.(?:original|immediate)_server_version=80413\*//\*!\*/;',
    r"SET @@SESSION\.GTID_NEXT= 'ANONYMOUS'/\*!\*/;",
    r'SET TIMESTAMP=\d+/\*!\*/;',
    r'SET @@session\.foreign_key_checks=1, @@session\.sql_auto_is_null=0, @@session\.unique_checks=1, @@session\.autocommit=1/\*!\*/;',
    r'SET @@session\.sql_mode=(?:1168113696|1168637984)/\*!\*/;',
    r'SET @@session\.auto_increment_increment=1, @@session\.auto_increment_offset=1/\*!\*/;',
    r'/\*!\\C (?:utf8mb4|latin1) \*//\*!\*/;',
    r'SET @@session\.character_set_client=(?:255,@@session\.collation_connection=255|8,@@session\.collation_connection=8),@@session\.collation_server=255/\*!\*/;',
    r'SET @@session\.lc_time_names=0/\*!\*/;',
    r'SET @@session\.collation_database=DEFAULT/\*!\*/;',
    r'/\*!80011 SET @@session\.default_collation_for_utf8mb4=255\*//\*!\*/;',
    r'BEGIN', r'/\*!\*/;', r'COMMIT/\*!\*/;',
    r"SET @@SESSION\.GTID_NEXT= 'AUTOMATIC' /\* added by mysqlbinlog \*/ /\*!\*/;",
    r'/\*!50003 SET COMPLETION_TYPE=@OLD_COMPLETION_TYPE\*/;',
    r'BINLOG_BLOCK',
]
BLOCK = re.compile(r"(?m)^BINLOG\s+'\s*([A-Za-z0-9+/=\s]+)'/\*!\*/;")

def validate(text,target=None):
    blocks=BLOCK.findall(text)
    if len(blocks)!=2: raise ValueError('BINLOG_BLOCK_COUNT')
    stripped=BLOCK.sub('BINLOG_BLOCK',text)
    lines=[x.strip() for x in stripped.splitlines() if x.strip() and not x.lstrip().startswith('#')]
    uses=[i for i,line in enumerate(lines) if re.match(r'(?i)^use\s',line)]
    if uses:
        if not target or not re.fullmatch(r'[a-z0-9_]{1,64}',target) or len(uses)!=1:
            raise ValueError('SQL_USE_UNEXPECTED')
        i=uses[0]
        if lines[i]!=f'use `{target}`/*!*/;' or not (lines.index("SET @@SESSION.GTID_NEXT= 'ANONYMOUS'/*!*/;") < i < lines.index('BEGIN')):
            raise ValueError('SQL_USE_TARGET')
        lines.pop(i)
    for line in lines:
        if not any(re.fullmatch(pattern,line) for pattern in PATTERNS):
            raise ValueError('SQL_ENVELOPE_UNKNOWN')
    sequence = [PATTERNS[i] for i in (0,1,2,3,23,5,6,7,7,8,9,10,11,12,13,14,15,16,17,18,19,23,20,21,4,22,0)]
    if len(lines)!=len(sequence) or any(not re.fullmatch(p,line) for p,line in zip(sequence,lines)):
        raise ValueError('SQL_ENVELOPE_ORDER')
    if lines[0] != '/*!50530 SET @@SESSION.PSEUDO_SLAVE_MODE=1*/;' or lines[-1] != '/*!50530 SET @@SESSION.PSEUDO_SLAVE_MODE=0*/;':
        raise ValueError('SQL_ENVELOPE_MODE')
    if 'original_server_version' not in lines[7] or 'immediate_server_version' not in lines[8]:
        raise ValueError('SQL_VERSION_ORDER')
    return blocks
