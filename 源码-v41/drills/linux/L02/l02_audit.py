"""Validate one raw Linux audit event without writing or exposing log content.

Callers are responsible for bounded, root-trusted audit capture and binding the
journal to the current boot. Unknown formats fail closed.
"""
import re
from l02_policy import require

PREFIX = re.compile(r'^type=([A-Z_]+) msg=audit\((\d+)\.(\d+):(\d+)\):\s*(.*)$')
FIELD = re.compile(r'(?:^|\s)([a-zA-Z_][a-zA-Z0-9_]*)=("[^"\n]*"|[^\s]+)')


def audit_fields(body):
    result = {}
    for match in FIELD.finditer(body):
        key, value = match.groups()
        require(key not in result, 'duplicate audit field')
        result[key] = value.strip('"')
    return result


def socket_address(value):
    require(re.fullmatch(r'[0-9A-Fa-f]+', value or '') is not None and len(value) % 2 == 0, 'invalid audit sockaddr')
    raw = bytes.fromhex(value)
    require(len(raw) >= 8, 'short audit sockaddr')
    # Linux sockaddr family is native-endian on the x86-64 lab; port is network order.
    require(raw[:2] in (b'\x02\x00', b'\x0a\x00'), 'unsupported address family')
    if raw[:2] == b'\x02\x00':
        require(len(raw) >= 16 and raw[4:8] == b'\x7f\x00\x00\x01', 'unexpected IPv4 bind address')
    else:
        require(len(raw) >= 28 and raw[8:24] == b'\0'*15+b'\x01', 'unexpected IPv6 bind address')
    return int.from_bytes(raw[2:4], 'big')


def verify_denial(lines, *, min_seconds, max_seconds, pid, executable, port, expected_target_type,
                  allow_missing_sockaddr=False):
    """Require same audit serial, PID, executable, target label and sockaddr.

    Return event identity only, never raw records. Exact AVC/SOCKADDR co-location
    is required; if the host audit policy emits no sockaddr this refuses.
    """
    require(type(pid) is int and pid > 0 and type(port) is int and 1024 <= port <= 65535, 'invalid identity')
    require(type(min_seconds) is int and type(max_seconds) is int and min_seconds <= max_seconds, 'invalid time window')
    require(executable == '/usr/sbin/nginx', 'unexpected executable')
    require(re.fullmatch(r'[a-zA-Z0-9_]+_t',expected_target_type or '') is not None, 'invalid target type')
    groups={}
    for line in lines:
        m=PREFIX.fullmatch(line.strip())
        if not m: continue
        kind,sec,fraction,serial,body=m.groups()
        key=(int(sec),fraction,serial)
        if min_seconds <= key[0] <= max_seconds:
            groups.setdefault(key,[]).append((kind,body))
    hits=[]
    for key, records in groups.items():
        avc=[]; syscall=[]; sockaddr=[]
        for kind,body in records:
            fields=audit_fields(body)
            if kind=='AVC' and re.search(r'\bdenied\s+\{\s*name_bind\s*\}',body): avc.append(fields)
            elif kind=='SYSCALL': syscall.append(fields)
            elif kind=='SOCKADDR': sockaddr.append(fields)
        if len(avc)!=1 or len(syscall)!=1 or len(sockaddr)>1: continue
        a,s=avc[0],syscall[0]
        if (a.get('pid') != str(pid) or s.get('pid') != str(pid) or s.get('exe') != executable or
            s.get('success') != 'no' or a.get('tclass') != 'tcp_socket' or
            not re.fullmatch(r'[^:]+:[^:]+:httpd_t(?::[^\s]+)?',a.get('scontext','')) or
            not re.fullmatch(r'[^:]+:[^:]+:'+re.escape(expected_target_type)+r'(?::[^\s]+)?',a.get('tcontext',''))):
            continue
        if sockaddr:
            if socket_address(sockaddr[0].get('saddr')) != port: continue
            source='audit_sockaddr'
        else:
            # Only a caller with independent trusted journal evidence for the
            # address may opt in; verify the x86-64 bind syscall itself.
            if not allow_missing_sockaddr or s.get('arch')!='c000003e' or s.get('syscall')!='49': continue
            source='journal_message'
        hits.append((key,source))
    require(len(hits)==1, 'no unique correlated AVC and bind event')
    key,source=hits[0]
    return {'audit_seconds':key[0], 'audit_fraction':key[1], 'audit_serial':key[2], 'address_source':source}
