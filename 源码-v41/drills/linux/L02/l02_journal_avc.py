"""Correlate journal metadata and an audit bind denial for one L02 invocation.

Only metadata and digests are returned. The caller supplies records from a
root-trusted current-boot journal and audit source and must authenticate the
systemd unit and protected PREPARED state before calling.
"""
import hashlib
import re
from l02_policy import Refused, require
from l02_audit import verify_denial


def correlate(records, audit_lines, *, run_id, boot_id, invocation, port,
              started_epoch, ended_epoch, target_type='port_t', allow_journal_port=False):
    require(re.fullmatch(r'[0-9a-f]{24}',run_id or '') is not None,'invalid run id')
    require(re.fullmatch(r'[0-9a-f]{32}',boot_id or '') is not None,'invalid journal boot id')
    require(re.fullmatch(r'[0-9a-f]{32}',invocation or '') is not None,'invalid invocation')
    require(type(port) is int and 1024<=port<=65535,'invalid port')
    require(type(started_epoch) is int and type(ended_epoch) is int and
            started_epoch>0 and 0<=ended_epoch-started_epoch<=120,'invalid start window')
    unit='opsdrill-l02-'+run_id+'.service'
    needle='bind() to 127.0.0.1:'+str(port)+' failed (13: Permission denied)'
    matches=[]
    for row in records:
        require(isinstance(row,dict),'invalid journal record')
        if (row.get('_SYSTEMD_UNIT')!=unit or row.get('_BOOT_ID')!=boot_id or
            row.get('_SYSTEMD_INVOCATION_ID')!=invocation or row.get('_EXE') not in (None,'/usr/sbin/nginx')):
            continue
        pid=row.get('_PID'); stamp=row.get('__REALTIME_TIMESTAMP'); message=row.get('MESSAGE')
        if (not isinstance(pid,str) or not re.fullmatch(r'[1-9][0-9]*',pid) or
            not isinstance(stamp,str) or not stamp.isdigit() or not isinstance(message,str) or
            needle not in message):
            continue
        secs=int(stamp)//1000000
        if not started_epoch<=secs<=ended_epoch: continue
        try:
            event=verify_denial(audit_lines,min_seconds=max(started_epoch,secs-2),
                                max_seconds=min(ended_epoch,secs+2),pid=int(pid),
                                executable='/usr/sbin/nginx',port=port,expected_target_type=target_type,
                                allow_missing_sockaddr=allow_journal_port)
        except Refused:
            continue
        matches.append({'pid':int(pid),'journal_timestamp_us':int(stamp),
                        'journal_message_sha256':hashlib.sha256(message.encode('utf-8')).hexdigest(),
                        'audit':event,'invocation':invocation,'boot_id':boot_id})
    require(len(matches)==1,'no unique journal/AVC correlation')
    return matches[0]
