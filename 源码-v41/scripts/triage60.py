#!/usr/bin/env python3
"""Bounded, read-only host triage; output may contain local operational data."""
import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import time

VERSION = '0.1.0'
CHECKS = [
    ('date', ['date', '-Is']), ('host', ['hostnamectl']),
    ('uptime', ['uptime']), ('memory', ['free', '-h']),
    ('vmstat', ['vmstat', '1', '2']), ('filesystems', ['df', '-hT']),
    ('inodes', ['df', '-i']), ('block_devices', ['lsblk']),
    ('socket_summary', ['ss', '-s']), ('listeners', ['ss', '-lntp']),
    ('failed_services', ['systemctl', '--failed', '--no-legend']),
    ('journal_errors', ['journalctl', '-p', 'err', '-b', '--no-pager', '-n', '50']),
    ('deleted_open_files', ['lsof', '+L1']),
    ('iostat', ['iostat', '-xz', '1', '2']),
    ('pidstat', ['pidstat', '-d', '1', '2']),
    ('sar_network', ['sar', '-n', 'DEV', '1', '2']),
]


def collect(name, argv, timeout=4):
    start = time.monotonic()
    result = {'name': name, 'command': argv, 'status': 'UNKNOWN', 'exit_code': None}
    if not shutil.which(argv[0]):
        result['reason'] = 'command unavailable'
        return result
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False, env={**os.environ, 'LC_ALL': 'C'})
        result.update(status='OK' if proc.returncode == 0 else 'ERROR',
                      exit_code=proc.returncode,
                      stdout=proc.stdout[:32768].decode('utf-8', 'replace'),
                      stderr=proc.stderr[:4096].decode('utf-8', 'replace'),
                      truncated=len(proc.stdout) > 32768 or len(proc.stderr) > 4096)
        if name in ('journal_errors', 'deleted_open_files'):
            # Journal messages and file paths can contain credentials or other private data.
            result['stdout'] = '%d lines; raw content omitted\n' % len(proc.stdout.splitlines())
            result['stderr'] = ''
    except subprocess.TimeoutExpired:
        result['reason'] = 'timeout'
    except OSError as exc:
        result['reason'] = type(exc).__name__
    result['duration_ms'] = round((time.monotonic() - start) * 1000)
    return result


def main():
    parser = argparse.ArgumentParser(description='Read-only host triage, output may contain sensitive host data')
    parser.add_argument('--json', action='store_true', help='write structured result to stdout')
    args = parser.parse_args()
    started = time.monotonic()
    result = {'version': VERSION, 'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'clock': 'system wall clock; synchronization not assumed', 'checks': []}
    for name, argv in CHECKS:
        remaining = 55 - (time.monotonic() - started)
        if remaining <= 0:
            result['checks'].append({'name': name, 'command': argv, 'status': 'UNKNOWN',
                                     'exit_code': None, 'reason': 'overall deadline'})
        else:
            result['checks'].append(collect(name, argv, timeout=min(4, remaining)))
    result['duration_ms'] = round((time.monotonic() - started) * 1000)
    if args.json:
        print(json.dumps(result, ensure_ascii=False))
    else:
        print('triage60 version=%s timestamp=%s' % (VERSION, result['timestamp']))
        for check in result['checks']:
            print('\n[%s] %s exit=%s' % (check['name'], check['status'], check['exit_code']))
            if check.get('reason'):
                print(check['reason'])
            for key in ('stdout', 'stderr'):
                if check.get(key):
                    print(check[key], end='' if check[key].endswith('\n') else '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
