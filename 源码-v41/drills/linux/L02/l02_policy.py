"""L02 policy and recovery state machine. No host adapter is provided.

This module intentionally cannot issue system commands or access host resources.
The adapter must enforce every documented invariant before production use.
"""
from __future__ import annotations
from dataclasses import dataclass
import re

class Refused(Exception):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def parse_ports(text):
    """Parse semanage port -l output; resolve overlaps conservatively per port."""
    entries = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('SELinux Port Type'):
            continue
        match = re.fullmatch(r'\s*([a-zA-Z0-9_]+)\s+(tcp|udp|sctp|dccp)\s+([0-9,\s-]+)\s*', line)
        require(match is not None, 'unparseable SELinux port listing')
        typ, proto, ports = match.groups()
        for item in ports.split(','):
            m = re.fullmatch(r'\s*(\d+)(?:\s*-\s*(\d+))?\s*', item)
            require(m is not None, 'unparseable port range')
            low = int(m.group(1)); high = int(m.group(2) or low)
            require(1 <= low <= high <= 65535, 'invalid port range')
            if proto == 'tcp': entries.append((low, high, typ))
    entries.sort()
    return entries


def port_type(entries, port):
    require(type(port) is int and 1024 <= port <= 65535, 'invalid candidate port')
    matches = {typ for lo, hi, typ in entries if lo <= port <= hi}
    specific = matches - {'unreserved_port_t'}
    require(len(specific) <= 1, 'ambiguous overlapping port types')
    if specific: return next(iter(specific))
    return 'unreserved_port_t' if matches else None

@dataclass(frozen=True)
class Observation:
    enforcing: bool
    guard: bool
    config_owned: bool
    config_digest: str
    baseline_healthy: bool
    port_available: bool
    tcp_policy: str | None
    watchdog_armed: bool


def preflight(o):
    require(o.guard and o.enforcing, 'guard or SELinux failed')
    require(o.config_owned and re.fullmatch(r'[0-9a-f]{64}', o.config_digest) is not None, 'unsafe config')
    require(o.baseline_healthy and o.port_available, 'baseline unhealthy or port occupied')
    # Never modify a pre-existing mapping, even when non-http (e.g. 8081).
    require(o.tcp_policy is None, 'port already mapped')
    require(o.watchdog_armed, 'recovery watchdog not armed')


def recovered(o, expected_digest, health_status, active, listen_correct, nginx_config_ok):
    """Recovery must be demonstrated through actual independent observations."""
    return bool(o.guard and o.enforcing and o.config_owned and
                o.config_digest == expected_digest and o.tcp_policy == 'http_port_t' and
                active and listen_correct and nginx_config_ok and health_status == 200)


def reset_decision(current_digest, original_digest, fault_digest, current_mapping,
                   mapping_owned, original_mapping, healthy):
    """Return a safe action plan; foreign modifications are never overwritten."""
    require(current_digest in (original_digest, fault_digest), 'configuration changed externally')
    require(original_mapping is None, 'pre-existing port mapping')
    require(current_mapping is None or (current_mapping == 'http_port_t' and mapping_owned),
            'foreign port mapping')
    actions = []
    if current_digest == fault_digest and fault_digest != original_digest:
        actions.append('restore_owned_config')
    if current_mapping == 'http_port_t':
        actions.append('remove_owned_mapping')
    if actions or not healthy:
        actions.append('verify_or_recover_owned_service')
    return actions
