#!/usr/bin/env python3
"""Summarize Nginx combined or JSON access logs without emitting raw log lines."""
import argparse
import collections
import datetime
import hashlib
import ipaddress
import json
import math
import re
import sys
from urllib.parse import urlsplit

COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"\r\n]*)" (\d{3}) (?:\d+|-)')


def address_group(value):
    try:
        addr = ipaddress.ip_address(value)
        return str(ipaddress.ip_network('%s/%s' % (addr, 24 if addr.version == 4 else 64), strict=False))
    except ValueError:
        return 'UNKNOWN'


def uri_path(request):
    pieces = str(request).split()
    value = pieces[1] if len(pieces) >= 2 else str(request)
    try:
        path = urlsplit(value).path
    except ValueError:
        return 'UNKNOWN'
    if not path.startswith('/'):
        return 'UNKNOWN'
    if re.fullmatch(r'/orders/[0-9]+', path):
        return '/orders/:id'
    if path in ('/', '/health', '/ready', '/orders', '/api/v1/orders', '/api/v1/orders/slow'):
        return path
    return 'path#' + hashlib.sha256(path.encode('utf-8', 'replace')).hexdigest()[:16]


def number(value):
    try:
        value = float(value)
        return value if math.isfinite(value) and value >= 0 else None
    except (TypeError, ValueError):
        return None


def latency_summary(values):
    values = sorted(values)
    n = len(values)
    if not n:
        return {'samples': 0, 'mean': None, 'p50': None, 'p95': None}
    return {'samples': n, 'mean': sum(values)/n, 'p50': values[math.ceil(n*.5)-1],
            'p95': values[math.ceil(n*.95)-1] if n >= 20 else None}


def parse_line(line):
    if line.lstrip().startswith('{'):
        try:
            obj = json.loads(line)
            status = int(obj['status'])
            stamp = str(obj.get('time_local', obj.get('time_iso8601', '')))
            return {'status':status, 'address':str(obj.get('remote_addr','')),
                    'request':str(obj.get('request','')), 'time':stamp,
                    'request_time':obj.get('request_time'),
                    'upstream_connect_time':obj.get('upstream_connect_time'),
                    'upstream_header_time':obj.get('upstream_header_time'),
                    'upstream_response_time':obj.get('upstream_response_time')}
        except (ValueError, TypeError, KeyError, AttributeError):
            return None
    match = COMBINED.match(line)
    if not match:
        return None
    address, stamp, request, status = match.groups()
    return {'status':int(status), 'address':address, 'request':request, 'time':stamp}


def summarize(lines, limit=10):
    out = {'requests':0, 'malformed':0, 'status':{}, 'top_networks':[], 'top_uri_paths':[],
           'latency_seconds':{}, 'slow_requests':[], 'upstream':{}, 'window':None}
    statuses, networks, uris = collections.Counter(), collections.Counter(), collections.Counter()
    times, slow, stamps = [], [], []
    upstream = {k:collections.Counter() for k in ('upstream_connect_time','upstream_header_time','upstream_response_time')}
    for line in lines:
        item = parse_line(line)
        if item is None or not 100 <= item['status'] <= 599:
            out['malformed'] += 1
            continue
        out['requests'] += 1
        code = item['status']
        statuses[str(code // 100) + 'xx'] += 1
        if code in (502, 504): statuses[str(code)] += 1
        networks[address_group(item['address'])] += 1
        path = uri_path(item['request'])
        uris[path] += 1
        stamp = item['time']
        for fmt in ('%d/%b/%Y:%H:%M:%S %z', '%Y-%m-%dT%H:%M:%S%z'):
            try:
                stamps.append(datetime.datetime.strptime(stamp,fmt).astimezone(datetime.timezone.utc))
                break
            except ValueError:
                continue
        sec = number(item.get('request_time'))
        if sec is not None:
            times.append(sec)
            slow.append((sec, path))
        for name, counts in upstream.items():
            raw = item.get(name)
            if raw is None or raw == '-' or raw == '':
                counts['missing'] += 1
                continue
            attempts = re.split(r'[, :]+', str(raw))
            parsed = [number(x) for x in attempts if x]
            counts['multiple_attempts' if len(parsed) > 1 else 'single_attempt'] += 1
            counts['invalid_values'] += sum(v is None for v in parsed)
    n = out['requests']
    out['status'] = {k:{'count':statuses[k], 'ratio':statuses[k]/n if n else None} for k in ('2xx','4xx','5xx','502','504')}
    out['top_networks'] = networks.most_common(limit)
    out['top_uri_paths'] = uris.most_common(limit)
    out['latency_seconds'] = latency_summary(times)
    out['slow_requests'] = [{'seconds':s,'path':p} for s,p in sorted(slow,reverse=True)[:limit]]
    out['upstream'] = {k:dict(v) for k,v in upstream.items()}
    out['window'] = {'start_utc':min(stamps).isoformat(),'end_utc':max(stamps).isoformat(),
                     'timestamp_samples':len(stamps)} if stamps else None
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='Nginx access log, or - for stdin')
    parser.add_argument('--top', type=int, default=10, choices=range(1,101), metavar='1..100')
    args = parser.parse_args()
    try:
        if args.file == '-': result = summarize(sys.stdin, args.top)
        else:
            with open(args.file, encoding='utf-8', errors='replace') as lines:
                result = summarize(lines, args.top)
    except OSError as exc:
        print('log read error: '+type(exc).__name__, file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
