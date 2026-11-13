"""Pure ownership proof for a single local SELinux TCP port addition.

These checks do not serialize external semanage clients. A real adapter must
hold the policy-management lock across each command and post-operation proof;
if that cannot be demonstrated, it must refuse all mutation.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from l02_policy import Refused, parse_ports, port_type, require

RID = re.compile(r'^[0-9a-f]{24}$')


def canonical(text):
    """Retain UDP and TCP local entries; fail closed on unexpected format."""
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('SELinux Port Type'):
            continue
        m = re.fullmatch(r'\s*([a-zA-Z0-9_]+)\s+(tcp|udp)\s+([0-9,\s-]+)\s*',line)
        require(m is not None, 'invalid local policy output')
        typ,proto,ports=m.groups()
        for item in ports.split(','):
            p=re.fullmatch(r'\s*(\d+)(?:\s*-\s*(\d+))?\s*',item)
            require(p is not None,'invalid local port range')
            lo=int(p.group(1)); hi=int(p.group(2) or lo)
            require(1 <= lo <= hi <= 65535,'invalid local port range')
            rows.append((proto,lo,hi,typ))
    rows.sort()
    for a,b in zip(rows,rows[1:]):
        require(a[0] != b[0] or a[2] < b[1], 'overlapping local port rules')
    return tuple(rows)


def digest(rows):
    return hashlib.sha256(json.dumps(rows,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def has_coverage(rows, proto, port):
    return any(p==proto and lo<=port<=hi for p,lo,hi,_ in rows)

@dataclass(frozen=True)
class MappingIntent:
    run_id: str
    port: int
    before: tuple

    def validate(self):
        require(isinstance(self.run_id,str) and RID.fullmatch(self.run_id), 'bad run id')
        require(type(self.port) is int and 1024 <= self.port <= 65535, 'bad port')
        require(not has_coverage(self.before,'tcp',self.port), 'port locally mapped')


def authorize_add(intent, effective, current_local):
    intent.validate()
    require(current_local == intent.before,'local policy drift before add')
    require(port_type(effective,intent.port) is None,'effective policy already covers port')


def expected_after(intent):
    intent.validate()
    return tuple(sorted((*intent.before,('tcp',intent.port,intent.port,'http_port_t'))))


def prove_after_add(intent, actual, command_completed, exclusive_lock_proven):
    """A matching snapshot by itself does not establish creation ownership."""
    intent.validate()
    require(command_completed and exclusive_lock_proven, 'add provenance ambiguous')
    require(actual == expected_after(intent), 'local policy drift after add')
    return digest(actual)


def authorize_delete(intent, actual, receipt_digest, exclusive_lock_proven):
    intent.validate()
    require(exclusive_lock_proven, 'policy lock unproven')
    require(isinstance(receipt_digest,str) and re.fullmatch(r'[0-9a-f]{64}',receipt_digest), 'missing add receipt')
    require(actual == expected_after(intent) and digest(actual)==receipt_digest, 'mapping absent or policy drift')
    return True
