#!/usr/bin/env python3
"""Strict parser for the one-run ownership receipt emitted by L03 inject."""
import json
import re
import sys
from pathlib import Path

RUN_ID = re.compile(r'^[0-9a-f]{24}$')
RECEIPT = 'L03_RUN_OWNER_V1'


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('RECEIPT_DUPLICATE_KEY')
        obj[key] = value
    return obj


def parse_receipt_bytes(raw):
    if not raw or len(raw) > 4096:
        raise ValueError('RECEIPT_SIZE')
    # Exactly one JSON object is accepted. Extra stdout is ambiguous ownership.
    lines = [line for line in raw.decode('utf-8', 'strict').splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError('RECEIPT_LINE_COUNT')
    obj = json.loads(lines[0], object_pairs_hook=unique_object)
    if not isinstance(obj, dict) or set(obj) != {'receipt', 'run_id', 'unit'}:
        raise ValueError('RECEIPT_SCHEMA')
    rid = obj['run_id']
    if obj['receipt'] != RECEIPT or not isinstance(rid, str) or not RUN_ID.fullmatch(rid):
        raise ValueError('RECEIPT_ID')
    unit = 'opsdrill-l03-' + rid + '.service'
    if obj['unit'] != unit:
        raise ValueError('RECEIPT_UNIT')
    return rid, unit


def main(argv):
    if len(argv) != 3 or argv[1] != 'receipt':
        raise SystemExit('USAGE: l03_fasttrack_guard.py receipt <inject stdout file>')
    with Path(argv[2]).open('rb') as handle:
        raw = handle.read(4097)
    rid, unit = parse_receipt_bytes(raw)
    print(rid + '\t' + unit)


if __name__ == '__main__':
    try:
        main(sys.argv)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print('INVALID_OWNER_RECEIPT: ' + str(exc), file=sys.stderr)
        raise SystemExit(2)
