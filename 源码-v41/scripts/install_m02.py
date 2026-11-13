#!/usr/bin/env python3
"""Install the reviewed M02 files without overwriting existing objects."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

# SHA-256 of the exact source bytes, not newline-normalized text.
MANIFEST = {'m02_deadlock.py': '5d41a8b7feb577b22a358f3497e1a4eb1c53669a1fbf179a49ca9add16c065c9', 'm02_launcher.py': '3d6d8fad99fe5dd0e9ddc85450cb4bb94ae835053cd325d587a9066a418eb11d'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def guard():
    require(os.geteuid() == 0, 'root required')
    fd = os.open('/etc/opsdrill-lab', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= 64 and
                os.read(fd, 65).strip() == b'ops-drill-kit', 'unsafe lab marker')
    finally:
        os.close(fd)
    result = subprocess.run(['/usr/bin/systemd-detect-virt', '--vm'], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'},
                            timeout=10, check=False)
    require(result.returncode == 0 and result.stdout.strip() == 'vmware', 'VMware guest required')


def secure_file(fd):
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= 1024 * 1024, 'unsafe file')
        data = stream.read(1024 * 1024 + 1)
        require(len(data) == st.st_size, 'file changed')
        return data


def source_files(source):
    path = Path(source).absolute()
    for item in (path, *path.parents):
        st = os.lstat(item)
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'unsafe source directory')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        result = {}
        for name, digest in MANIFEST.items():
            data = secure_file(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd))
            require(hashlib.sha256(data).hexdigest() == digest, 'source digest mismatch: ' + name)
            result[name] = data
    finally:
        os.close(fd)
    result['manifest.json'] = (json.dumps(MANIFEST, sort_keys=True) + '\n').encode('ascii')
    return result


def secure_installer():
    path = Path(__file__).absolute()
    for parent in path.parents:
        st = os.lstat(parent)
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                'unsafe installer directory')
    secure_file(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC))


def install(files, root='/'):
    require(set(files) == set(MANIFEST) | {'manifest.json'}, 'invalid module set')
    expected = dict(MANIFEST)
    expected['manifest.json'] = hashlib.sha256((json.dumps(MANIFEST, sort_keys=True) + '\n').encode('ascii')).hexdigest()
    require(all(hashlib.sha256(files[name]).hexdigest() == digest for name, digest in expected.items()),
            'invalid install content')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in ('usr', 'local', 'libexec', 'opsdrill', 'm02'):
            try:
                os.mkdir(part, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            st = os.fstat(child)
            if not (stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022):
                os.close(child)
                raise RuntimeError('unsafe installation directory')
            os.close(fd)
            fd = child
        require(set(os.listdir(fd)) <= set(expected), 'unknown installation file')
        missing = []
        for name, digest in expected.items():
            try:
                item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                missing.append(name)
                continue
            require(hashlib.sha256(secure_file(item)).hexdigest() == digest, 'existing file differs: ' + name)
        for name in missing:
            temp = '.m02-' + secrets.token_hex(16)
            out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                with os.fdopen(out, 'wb') as stream:
                    stream.write(files[name])
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o644)
                    os.fsync(stream.fileno())
                os.link(temp, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                os.unlink(temp, dir_fd=fd)
            finally:
                try:
                    os.unlink(temp, dir_fd=fd)
                except FileNotFoundError:
                    pass
        os.fsync(fd)
        return len(missing)
    finally:
        os.close(fd)



def verify_dependencies():
    """Require installed, verified Rocky system RPMs; never install packages."""
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}
    packages=['python3.11','python3.11-libs','python3.11-PyMySQL',
              'python3.11-cryptography','python3.11-cffi','python3.11-pycparser']
    result=subprocess.run(['/usr/bin/rpm','-V',*packages],stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                          env=env,timeout=60,check=False)
    require(result.returncode==0 and not result.stdout.strip(), 'RPM verification failed')
    site=Path('/usr/lib/python3.11/site-packages')
    for directory in (site,Path('/usr/lib64/python3.11/site-packages')):
        for item in (directory,*directory.parents):
            st=os.lstat(item)
            require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,
                    'unsafe system package directory')
        for root,dirs,files in os.walk(directory,followlinks=False,onerror=lambda exc: (_ for _ in ()).throw(exc)):
            for name in dirs:
                st=os.lstat(os.path.join(root,name))
                require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,
                        'unsafe package directory')
            for name in files:
                st=os.lstat(os.path.join(root,name))
                require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode & 0o022,
                        'unsafe package file')
    source=site/'pymysql/__init__.py'
    result=subprocess.run(['/usr/bin/rpm','-qf','--qf','%{NAME}',str(source)],
                          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,env=env,timeout=10,check=False)
    require(result.returncode==0 and result.stdout=='python3.11-PyMySQL',
            'PyMySQL is not owned by the expected RPM')
    probe=("import sys; sys.path[:0] = ['/usr/lib/python3.11/site-packages', '/usr/lib64/python3.11/site-packages']; "
           "import pymysql,cryptography; from cryptography.hazmat.primitives.asymmetric import rsa,padding; print(pymysql.__file__)")
    result=subprocess.run(['/usr/bin/python3.11','-I','-S','-B','-c',probe],
                          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,env=env,timeout=15,check=False)
    require(result.returncode==0 and result.stdout.strip()==str(source),
            'isolated Python dependency probe failed')

def main():
    require(len(sys.argv) == 2, 'usage: install_m02.py REVIEWED_SOURCE_DIR')
    guard()
    # Caller must independently authenticate this installer; ownership is not provenance.
    secure_installer()
    files = source_files(sys.argv[1])
    verify_dependencies()
    count = install(files)
    print('M02 installed; new files:', count)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('M02 install refused:', exc, file=sys.stderr)
        sys.exit(2)
