#!/usr/bin/env python3
"""Install known L03 package files into /opt/ops-drill-kit, without overwriting edits."""
import hashlib
import pathlib
import sys
import zipfile

PROJECT = pathlib.Path('/opt/ops-drill-kit')
ALLOWED = {
    'drills/linux/L03/inject.sh',
    'drills/linux/L03/check.sh',
    'drills/linux/L03/reset.sh',
    'drills/linux/L03/l03_control.py',
    'tests/bats/l03.bats',
    'tests/python/test_l03.py',
    'scripts/fasttrack_l03.sh',
    'scripts/opsdrill_inventory.py',
    'scripts/l03_fasttrack_guard.py',
    'scripts/install_l03.py',
    'tests/python/test_l03_fasttrack.py',
    'tests/python/test_install_l03.py',
}
# These files are owned by the user's separate triage60 work and are never
# part of this installer. The archive is rejected if it tries to include them.
PROTECTED = {
    'scripts/triage60.py',
    'scripts/triage60.sh',
    'tests/unit/test_triage60.py',
}

def digest(data):
    return hashlib.sha256(data).digest()

def main(argv):
    if len(argv) != 2:
        raise SystemExit('USAGE: python3 install_l03.py <zip path>')
    if pathlib.Path.cwd().resolve() != PROJECT or not (PROJECT / 'lib/guard.sh').is_file():
        raise SystemExit('WRONG_PROJECT_ROOT_OR_GUARD_MISSING')
    with zipfile.ZipFile(argv[1]) as z:
        files = {n: z.read(n) for n in z.namelist() if not n.endswith('/') and n != 'README-L03.md'}
        if set(files) & PROTECTED:
            raise SystemExit('PROTECTED_USER_FILE_IN_PACKAGE')
        if set(files) != ALLOWED:
            raise SystemExit('PACKAGE_CONTENT_MISMATCH')
        # Entire preflight occurs before first write.
        for name, data in files.items():
            dest = PROJECT / name
            for part in (dest, *dest.parents):
                if part == PROJECT.parent:
                    break
                if part.is_symlink():
                    raise SystemExit('SYMLINK_PATH_REFUSED: ' + name)
            if dest.exists() and (not dest.is_file() or digest(dest.read_bytes()) != digest(data)):
                raise SystemExit('REFUSE_OVERWRITE: ' + name)
        count = 0
        for name, data in files.items():
            dest = PROJECT / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                with dest.open('xb') as f:
                    f.write(data)
                count += 1
    print(f'INSTALL_NO_OVERWRITE_PASS: created={count}, existing_identical={len(ALLOWED)-count}')

if __name__ == '__main__':
    main(sys.argv)
