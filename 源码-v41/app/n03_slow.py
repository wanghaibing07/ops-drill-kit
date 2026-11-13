"""Bounded, opt-in slow endpoint for the local N03 timeout exercise."""
import asyncio
import os
import re
import stat
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter()
_inflight = False
DELAY_SECONDS = 12
GATE_DIR = Path('/run/opsdrill-n03-gate')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
ROOT_UID = 0
MAX_GATE_TTL_NS = 120 * 1_000_000_000


def gate_active():
    """Accept only a root-owned gate that is valid for this boot and time."""
    try:
        dfd = os.open(GATE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            directory = os.fstat(dfd)
            if not (stat.S_ISDIR(directory.st_mode) and directory.st_uid == ROOT_UID and
                    stat.S_IMODE(directory.st_mode) == 0o755):
                return False
            fd = os.open('slow.trigger', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
            try:
                info = os.fstat(fd)
                if not (stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1 and
                        stat.S_IMODE(info.st_mode) == 0o644 and info.st_size <= 160):
                    return False
                data = os.read(fd, 161)
                if len(data) != info.st_size:
                    return False
                match = re.fullmatch(
                    rb'opsdrill-n03-504:([0-9a-f]{24}):'
                    rb'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):'
                    rb'([0-9]{1,20}):([0-9]{1,20})\n', data)
                if not match:
                    return False
                boot = BOOT_ID.read_text(encoding='ascii').strip().encode('ascii')
                created, expires = int(match.group(3)), int(match.group(4))
                now = time.monotonic_ns()
                return (match.group(2) == boot and 0 < expires - created <= MAX_GATE_TTL_NS and
                        created <= now < expires)
            finally:
                os.close(fd)
        finally:
            os.close(dfd)
    except (OSError, ValueError, UnicodeError):
        return False


@router.get('/api/v1/orders/slow')
async def slow_orders():
    global _inflight
    if os.environ.get('OPSDRILL_ENABLE_SLOW') != '1' or not gate_active():
        raise HTTPException(status_code=404, detail='Not found')
    if _inflight:
        raise HTTPException(status_code=429, detail='Slow drill is already running')
    _inflight = True
    try:
        await asyncio.sleep(DELAY_SECONDS)
        return {'status': 'slow drill completed'}
    finally:
        _inflight = False
