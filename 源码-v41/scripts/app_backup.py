"""Back up and verify explicit lab files; all paths are relative to LAB.

Example (run from a trusted lab account with no concurrent filesystem writers):
  python app_backup.py backup --lab /srv/opsdrill-lab --source app --dest backups/run1 --file config/a.yml --file bin/start.sh
  python app_backup.py restore --lab /srv/opsdrill-lab --backup backups/run1 --dest restores/run1

LAB must contain a regular .opsdrill-lab marker with text ops-drill-kit.
Destination parent directories must already exist. Each destination itself must be new.
This tool preserves bytes and ordinary permission bits, not ownership, timestamps or hard-link identity.
It assumes a trusted lab without concurrent filesystem attackers; stat checks detect common source changes.
The marker is a guardrail, not authentication; manifest hashes do not protect against deliberate tampering.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

MANIFEST = 'manifest.json'


def parts(value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise ValueError('invalid relative path')
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ('', '.', '..') for x in value.split('/')) or ':' in value:
        raise ValueError('invalid relative path: ' + value)
    return p.parts


def checked(root, rel, *, directory=False):
    current = root
    for name in parts(rel):
        current = current / name
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('link or reparse point: ' + str(current))
        if current != root.joinpath(*parts(rel)) and not stat.S_ISDIR(info.st_mode):
            raise ValueError('non-directory path component')
    if directory and not stat.S_ISDIR(info.st_mode):
        raise ValueError('expected directory')
    return current


def lab_root(value):
    if '..' in Path(value).parts:
        raise ValueError('lab path contains parent traversal')
    p = Path(value).absolute()
    # Inspect every existing component, including the lab itself.
    current = Path(p.anchor)
    for name in p.parts[1:]:
        current /= name
        st = current.lstat()
        if stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
            raise ValueError('lab path contains link or reparse point')
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError('lab path is not a directory')
    if p == Path(p.anchor):
        raise ValueError('filesystem root is not a lab')
    marker = p / '.opsdrill-lab'
    st = marker.lstat()
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400 or marker.read_text(encoding='utf-8').strip() != 'ops-drill-kit':
        raise ValueError('lab marker mismatch')
    return p


def new_dir(lab, rel):
    names = parts(rel)
    parent = lab if len(names) == 1 else checked(lab, '/'.join(names[:-1]), directory=True)
    dest = parent / names[-1]
    dest.mkdir(mode=0o700)  # exclusive: never reuse a destination
    return dest


def file_state(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, stat.S_IMODE(st.st_mode))


def copy_file(source, dest):
    st = source.lstat()
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise ValueError('input is not a regular file')
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(source, flags)
    with os.fdopen(fd, 'rb') as src, os.fdopen(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600), 'wb') as out:
        opened = os.fstat(src.fileno())
        if not stat.S_ISREG(opened.st_mode) or (st.st_dev, st.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('input changed while opening')
        initial = file_state(opened)
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            digest.update(chunk)
            out.write(chunk)
        if file_state(os.fstat(src.fileno())) != initial or (source.lstat().st_dev, source.lstat().st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('source changed while reading: ' + str(source))
        safe_mode = stat.S_IMODE(opened.st_mode) & 0o777
        if os.name != 'nt':
            os.fchmod(out.fileno(), 0o600)
        out.flush()
        os.fsync(out.fileno())
    return digest.hexdigest(), safe_mode


def destination_file(root, rel):
    names = parts(rel)
    current = root
    for name in names[:-1]:
        current = current / name
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            st = current.lstat()
            if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
                raise ValueError('unsafe destination component')
    return current / names[-1]


def validate_list(files):
    if not files:
        raise ValueError('empty file list')
    seen = set()
    for item in files:
        p = '/'.join(parts(item))
        normalized = os.path.normcase(p)
        reserved = os.path.normcase(MANIFEST)
        if normalized == reserved or normalized.startswith(reserved + '/') or normalized in {os.path.normcase(x) for x in seen}:
            raise ValueError('reserved or duplicate file')
        seen.add(p)
    normalized_seen = {os.path.normcase(p) for p in seen}
    if any(any(os.path.normcase('/'.join(p.split('/')[:i])) in normalized_seen for i in range(1, len(p.split('/')))) for p in seen):
        raise ValueError('file and directory paths conflict')
    return sorted(seen)


def backup(lab, source, dest, files):
    lab = lab_root(lab)
    source = checked(lab, source, directory=True)
    files = validate_list(files)
    # A new output under source can never be an input; prohibit overlapping trees.
    d = lab.joinpath(*parts(dest))
    if source == d or source in d.parents or d in source.parents:
        raise ValueError('source and backup must not overlap')
    output = new_dir(lab, dest)
    entries = []
    for item in files:
        src = checked(source, item)
        digest, mode = copy_file(src, destination_file(output, item))
        entries.append({'path': item, 'sha256': digest, 'mode': mode})
    with (output / MANIFEST).open('x', encoding='utf-8', newline='\n') as f:
        json.dump({'version': 1, 'files': entries}, f, sort_keys=True, indent=2)
        f.write('\n'); f.flush(); os.fsync(f.fileno())
    return output


def restore(lab, backup_dir, dest):
    lab = lab_root(lab)
    src = checked(lab, backup_dir, directory=True)
    d = lab.joinpath(*parts(dest))
    if src == d or src in d.parents or d in src.parents:
        raise ValueError('backup and restore must not overlap')
    manifest = checked(src, MANIFEST)
    if not stat.S_ISREG(manifest.lstat().st_mode):
        raise ValueError('invalid manifest')
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('duplicate manifest key: ' + key)
            obj[key] = value
        return obj
    with manifest.open('r', encoding='utf-8') as f:
        doc = json.load(f, object_pairs_hook=unique_object)
    if not isinstance(doc, dict) or set(doc) != {'version', 'files'} or type(doc['version']) is not int or doc['version'] != 1 or not isinstance(doc['files'], list):
        raise ValueError('invalid manifest')
    entries = doc['files']
    if any(not isinstance(e, dict) or set(e) != {'path', 'sha256', 'mode'} or type(e['mode']) is not int or not 0 <= e['mode'] <= 0o777 or not isinstance(e['sha256'], str) or len(e['sha256']) != 64 or any(c not in '0123456789abcdef' for c in e['sha256']) for e in entries):
        raise ValueError('invalid manifest entry')
    validate_list([e['path'] for e in entries])
    output = new_dir(lab, dest)
    for entry in entries:
        actual, _ = copy_file(checked(src, entry['path']), destination_file(output, entry['path']))
        if actual != entry['sha256']:
            raise ValueError('backup hash mismatch: ' + entry['path'])
        # Verify the independently written destination, not just the stream.
        with checked(output, entry['path']).open('rb') as f:
            h = hashlib.sha256()
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        if h.hexdigest() != entry['sha256']:
            raise ValueError('restore hash mismatch: ' + entry['path'])
        restored = checked(output, entry['path'])
        os.chmod(restored, entry['mode'])
        if stat.S_IMODE(restored.stat().st_mode) != entry['mode']:
            raise ValueError('restore mode mismatch: ' + entry['path'])
    return output


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='command', required=True)
    b = sub.add_parser('backup'); b.add_argument('--lab', required=True); b.add_argument('--source', required=True); b.add_argument('--dest', required=True); b.add_argument('--file', action='append', required=True)
    r = sub.add_parser('restore'); r.add_argument('--lab', required=True); r.add_argument('--backup', required=True); r.add_argument('--dest', required=True)
    args = p.parse_args(argv)
    try:
        out = backup(args.lab, args.source, args.dest, args.file) if args.command == 'backup' else restore(args.lab, args.backup, args.dest)
        print(json.dumps({'status': 'PASS', 'directory': str(out)}))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as e:
        print('FAILED: ' + str(e), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
