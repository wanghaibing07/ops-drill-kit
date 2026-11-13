#!/usr/bin/env python3
"""Check a backup checksum manifest and gzip integrity without extracting files."""
import argparse
import gzip
import hashlib
import json
import os
import re
import stat
import sys
import zlib

ENTRY = re.compile(r'^([0-9a-fA-F]{64}) [ *](.+)$')
MAX_INFLATED = 4 * 1024**3


def safe_name(base, raw):
    if os.path.isabs(raw):
        if os.path.dirname(os.path.normpath(raw)) != base:
            raise ValueError('manifest path outside backup directory')
        raw = os.path.basename(raw)
    if raw in ('', '.', '..') or '/' in raw or '\\' in raw or '\x00' in raw:
        raise ValueError('unsafe manifest filename')
    return raw


def verify(base):
    base = os.path.realpath(base)
    dirfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    result = {'status':'PASS', 'items':[]}
    try:
        fd = os.open('SHA256SUMS', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
        with os.fdopen(fd, encoding='utf-8') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise ValueError('manifest is not a regular file')
            manifest = f.read(65537)
        if len(manifest) > 65536:
            raise ValueError('manifest too large')
        seen = set()
        lines = manifest.splitlines()
        if not lines:
            raise ValueError('empty manifest')
        for line in lines:
            match = ENTRY.fullmatch(line)
            if not match:
                raise ValueError('malformed manifest')
            expected, raw = match.groups()
            name = safe_name(base, raw)
            if name in seen:
                raise ValueError('duplicate manifest entry')
            seen.add(name)
            item = {'name':name, 'checksum':'FAIL', 'gzip':'NOT_APPLICABLE'}
            try:
                f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
                with os.fdopen(f, 'rb') as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError('not a regular file')
                    digest = hashlib.sha256()
                    for chunk in iter(lambda:stream.read(1024*1024), b''):
                        digest.update(chunk)
                    item['checksum'] = 'PASS' if digest.hexdigest() == expected.lower() else 'FAIL'
                    if name.endswith('.gz'):
                        stream.seek(0)
                        count = 0
                        with gzip.GzipFile(fileobj=stream) as archive:
                            while True:
                                chunk = archive.read(1024*1024)
                                if not chunk: break
                                count += len(chunk)
                                if count > MAX_INFLATED:
                                    raise ValueError('gzip expansion limit exceeded')
                        item['gzip'] = 'PASS'
                    after = os.fstat(stream.fileno())
                    if (before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                        raise ValueError('file changed during verification')
            except (OSError, EOFError, ValueError, zlib.error):
                item['checksum'] = 'FAIL'
                item['error'] = 'unreadable, unsafe, or invalid archive'
                if name.endswith('.gz'): item['gzip'] = 'FAIL'
            if item['checksum'] != 'PASS' or item['gzip'] == 'FAIL':
                result['status'] = 'FAIL'
            result['items'].append(item)
        result['note'] = 'Integrity checks only; restore and data verification are separate.'
        return result
    finally:
        os.close(dirfd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', help='backup directory containing SHA256SUMS')
    args = parser.parse_args()
    try:
        result = verify(args.directory)
    except (OSError, ValueError, UnicodeError) as exc:
        print(json.dumps({'status':'FAIL','error':str(exc)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
