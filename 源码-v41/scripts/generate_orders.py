#!/usr/bin/env python3
"""Generate deterministic, synthetic OrderGuard TSV data outside the repo."""
import argparse
import csv
import hashlib
import json
import os
import random
import re
import stat
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path('/var/tmp/ops-drill-kit')
BASE_TIME = datetime(2026, 11, 8)
MAX_ROWS = 500_000
OTHER_MERCHANTS = tuple(range(1, 88)) + tuple(range(89, 501))


def make_row(number, rng):
    # Excluding 88 from the random pool makes every twentieth ID the only
    # special merchant, including when a run starts in the middle of a range.
    merchant = 88 if number % 20 == 0 else rng.choice(OTHER_MERCHANTS)
    user = rng.randint(1, 50_000)
    status = rng.choices(range(5), weights=(10, 25, 20, 35, 10))[0]
    amount = rng.randint(100, 99_900)
    channel = rng.choice(('card', 'wallet', 'bank'))
    created = BASE_TIME - timedelta(seconds=rng.randint(0, 180 * 86400))
    updated = created + timedelta(seconds=rng.randint(0, 86400))
    return (f'OG{number:012d}', merchant, user, status, amount, channel,
            created.strftime('%Y-%m-%d %H:%M:%S'), updated.strftime('%Y-%m-%d %H:%M:%S'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', type=int, required=True)
    parser.add_argument('--start-id', type=int, default=1)
    parser.add_argument('--seed', type=int, default=20261108)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('run as the unprivileged owner of the data directory')
    if not 1 <= args.rows <= MAX_ROWS or not 1 <= args.start_id <= MAX_ROWS or args.start_id + args.rows - 1 > MAX_ROWS:
        parser.error('requested ID range must stay within 1..500000')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.tsv', args.output):
        parser.error('output must be a simple .tsv filename')
    info = BASE_DIR.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise SystemExit('data directory must be a user-owned 0700 directory, not a symlink')
    target = BASE_DIR / args.output
    rng = random.Random(args.seed)
    for number in range(1, args.start_id):
        make_row(number, rng)
    fd, temp_name = tempfile.mkstemp(prefix='.orders-', dir=BASE_DIR)
    published = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f, delimiter='\t', lineterminator='\n')
            for number in range(args.start_id, args.start_id + args.rows):
                writer.writerow(make_row(number, rng))
            f.flush()
            os.fsync(f.fileno())
        # link fails atomically if target exists, including dangling symlinks.
        os.link(temp_name, target)
        published = True
        digest = hashlib.sha256()
        with target.open('rb') as f:
            for block in iter(lambda: f.read(1024 * 1024), b''):
                digest.update(block)
        special = (args.start_id + args.rows - 1) // 20 - (args.start_id - 1) // 20
        print(json.dumps({'status': 'success', 'rows': args.rows, 'seed': args.seed,
                          'start_id': args.start_id, 'end_id': args.start_id + args.rows - 1,
                          'merchant_88_rows': special, 'sha256': digest.hexdigest(),
                          'file': str(target), 'mode': '0600'}))
    finally:
        os.unlink(temp_name)
        if published:
            directory_fd = os.open(BASE_DIR, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)


if __name__ == '__main__':
    main()
