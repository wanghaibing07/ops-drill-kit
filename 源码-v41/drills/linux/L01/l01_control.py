#!/usr/bin/env python3
"""L01 inode drill, restricted to one private ext4 loop image in the VMware lab."""
import contextlib
import errno
import fcntl
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path

LAB=Path('/mnt/opsdrill')
BASE=LAB/'L01'
STATE='current.json'
LOCK='.controller.lock'
IMAGE_SIZE=64*1024*1024
FILE_LIMIT=2048
OWNER=0
RID=re.compile(r'^[0-9a-f]{24}$')
LOOP=re.compile(r'^/dev/loop[0-9]+$')
ENTRY=re.compile(r'^inode-[0-9]{4}$')


class Refused(Exception): pass


def require(ok,message):
    if not ok: raise Refused(message)


def guard():
    require(os.geteuid()==0,'ROOT_REQUIRED')
    p=subprocess.run(['systemd-detect-virt','--vm'],capture_output=True,text=True)
    require(p.returncode==0 and p.stdout.strip()=='vmware','NOT_VMWARE')
    marker=Path('/etc/opsdrill-lab')
    require(marker.is_file() and marker.read_bytes().rstrip(b'\n')==b'ops-drill-kit','BAD_MARKER')
    s=LAB.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid==OWNER and not s.st_mode&0o022 and LAB.resolve()==LAB,'UNSAFE_LAB')


def directory(path, create=False):
    if create:
        try: os.mkdir(path,0o700)
        except FileExistsError: pass
    s=os.lstat(path)
    require(stat.S_ISDIR(s.st_mode) and s.st_uid==OWNER and stat.S_IMODE(s.st_mode)==0o700,'UNSAFE_DIRECTORY')
    return s


@contextlib.contextmanager
def locked():
    directory(BASE,True)
    dfd=os.open(BASE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dfd)
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==OWNER and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'UNSAFE_LOCK')
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Refused('BUSY')
        yield dfd
    finally:
        os.close(fd);os.close(dfd)


def read_state(dfd):
    try: fd=os.open(STATE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dfd)
    except FileNotFoundError:return None
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==OWNER and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=8192,'UNSAFE_STATE')
        data=json.loads(os.read(fd,8193))
    finally:os.close(fd)
    require(isinstance(data,dict) and data.get('version')==1 and data.get('mode')=='inode','BAD_STATE')
    require(isinstance(data.get('run_id'),str) and RID.fullmatch(data['run_id']),'BAD_RUN_ID')
    require(data.get('phase') in ('STARTING','IMAGE_READY','LOOP_READY','MOUNTED','FAULT','RESETTING'),'BAD_PHASE')
    return data


def write_state(dfd,obj):
    name='.new-'+secrets.token_hex(8)
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dfd)
    try:
        content=(json.dumps(obj,sort_keys=True)+'\n').encode()
        view=memoryview(content)
        while view:
            n=os.write(fd,view);require(n>0,'STATE_WRITE');view=view[n:]
        os.fsync(fd)
    finally:os.close(fd)
    os.replace(name,STATE,src_dir_fd=dfd,dst_dir_fd=dfd);os.fsync(dfd)


def run_path(s):
    path=BASE/s['run_id']
    st=directory(path)
    require((st.st_dev,st.st_ino)==(s.get('run_dev'),s.get('run_ino')),'RUN_CHANGED')
    return path


def image_identity(s,run):
    image=run/'disk.img'
    info=image.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==OWNER and info.st_nlink==1 and
            stat.S_IMODE(info.st_mode)==0o600 and info.st_size==IMAGE_SIZE,'UNSAFE_IMAGE')
    require((info.st_dev,info.st_ino)==(s.get('image_dev'),s.get('image_ino')),'IMAGE_CHANGED')
    return image


def command(args,timeout=30):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
    require(p.returncode==0,'COMMAND_FAILED_'+Path(args[0]).name.upper())
    return p.stdout.strip()


def loop_backing(loop,image):
    require(bool(LOOP.fullmatch(loop)),'BAD_LOOP')
    st=os.stat(loop)
    require(stat.S_ISBLK(st.st_mode),'NOT_BLOCK_DEVICE')
    out=command(['losetup','--noheadings','--raw','--output','BACK-FILE',loop])
    require(bool(out) and '\n' not in out,'LOOP_BACKING_UNKNOWN')
    a=os.stat(out); b=image.stat()
    require((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'LOOP_BACKING_CHANGED')
    return st.st_rdev


def mount_source(mount):
    p=subprocess.run(['findmnt','--mountpoint',str(mount),'--noheadings','--raw','--output','SOURCE,FSTYPE'],capture_output=True,text=True,timeout=5)
    if p.returncode==1 and not p.stdout.strip():return None
    require(p.returncode==0,'FINDMNT_FAILED')
    lines=p.stdout.strip().splitlines()
    require(len(lines)==1 and len(lines[0].split())==2,'MOUNT_AMBIGUOUS')
    return tuple(lines[0].split())


def verify_mount(s,run):
    image=image_identity(s,run)
    mount=run/'mount'
    st=os.lstat(mount)
    require(stat.S_ISDIR(st.st_mode) and st.st_uid==OWNER,'MOUNT_PATH_UNSAFE')
    loop=s.get('loop')
    require(isinstance(loop,str) and LOOP.fullmatch(loop),'NO_KNOWN_LOOP')
    rdev=loop_backing(loop,image)
    require(rdev==s.get('loop_rdev'),'LOOP_DEVICE_CHANGED')
    source=mount_source(mount)
    if source is None:return image,mount,False
    require(source==(loop,'ext4') and os.stat(mount).st_dev==rdev,'UNEXPECTED_MOUNT')
    return image,mount,True


def check_contents(mount):
    names=os.listdir(mount)
    require(len(names)<=FILE_LIMIT+1,'TOO_MANY_FILES')
    for name in names:
        path=mount/name
        st=path.lstat()
        if name=='lost+found':
            require(stat.S_ISDIR(st.st_mode) and st.st_uid==OWNER and not os.listdir(path),'UNEXPECTED_LOST_FOUND')
        else:
            require(bool(ENTRY.fullmatch(name)) and stat.S_ISREG(st.st_mode) and st.st_uid==OWNER and st.st_nlink==1 and st.st_size==0,'UNKNOWN_MOUNT_CONTENT')


def probe_writable(mount):
    """Create and remove one owned, empty probe on the verified mount."""
    dfd=os.open(mount,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for i in range(1024,FILE_LIMIT):
            name='inode-%04d'%i
            try:
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dfd)
            except FileExistsError:
                continue
            os.close(fd)
            os.unlink(name,dir_fd=dfd)
            return
        raise Refused('NO_PROBE_NAME')
    finally:
        os.close(dfd)


def verify_logrotate():
    try:
        import l01_logrotate
        l01_logrotate.verify()
    except ImportError:
        raise Refused('LOGROTATE_VALIDATOR_UNAVAILABLE')
    except (OSError, subprocess.TimeoutExpired, l01_logrotate.PolicyError) as exc:
        raise Refused(str(exc) if isinstance(exc, l01_logrotate.PolicyError) else 'LOGROTATE_CHECK_FAILED')


def inspect_clean():
    guard()
    if not os.path.lexists(BASE):
        print(json.dumps({'status':'CLEAN'})); return 0
    with locked() as dfd:
        require(read_state(dfd) is None and set(os.listdir(BASE))=={LOCK},'NOT_CLEAN')
    print(json.dumps({'status':'CLEAN'})); return 0


def check(expected_run_id=None):
    guard()
    if not os.path.lexists(BASE):
        require(expected_run_id is None,'RUN_ID_MISMATCH')
        print(json.dumps({'status':'CLEAN'}));return 0
    with locked() as dfd:
        s=read_state(dfd)
        if s is None:
            require(expected_run_id is None,'RUN_ID_MISMATCH')
            require(set(os.listdir(BASE))=={LOCK},'ORPHAN_RESOURCES')
            print(json.dumps({'status':'CLEAN'}));return 0
        if expected_run_id is not None: require(s['run_id']==expected_run_id,'RUN_ID_MISMATCH')
        run=run_path(s)
        require(s['phase']=='FAULT','INCOMPLETE_RUN_REQUIRES_RESET')
        _,mount,mounted=verify_mount(s,run)
        require(mounted,'MOUNT_MISSING')
        check_contents(mount)
        v=os.statvfs(mount)
        require(v.f_files>0 and 0<=v.f_ffree<=v.f_files,'INVALID_INODE_COUNTS')
        # A successful check must demonstrate recovery, not merely observe a fault.
        recovered = v.f_ffree * 10 >= v.f_files
        if recovered:
            probe_writable(mount)
            verify_logrotate()
        print(json.dumps({'status':'RECOVERED' if recovered else 'FAULT_PRESENT',
                          'mode':'inode','free_inodes':v.f_ffree,'total_inodes':v.f_files}))
        return 0 if recovered else 1


def reset_locked(dfd,s):
    run=run_path(s)
    require(set(os.listdir(run))<= {'disk.img','mount'},'UNKNOWN_RUN_CONTENT')
    image=image_identity(s,run)
    mount=run/'mount'
    require(os.path.lexists(mount),'MOUNT_DIRECTORY_MISSING')
    if s.get('loop'):
        source=mount_source(mount)
        if source is not None:
            _,mount,mounted=verify_mount(s,run)
            require(mounted,'MOUNT_MISSING')
            check_contents(mount)
            command(['umount','--',str(mount)],timeout=10)
            require(mount_source(mount) is None,'UMOUNT_FAILED')
        # An earlier reset may have detached the device before being interrupted.
        # Only detach when this exact image is still attached to this exact device.
        attached=command(['losetup','--noheadings','--raw','--associated',str(image),'--output','NAME'])
        if attached:
            require(attached==s['loop'],'UNEXPECTED_LOOP_ATTACHMENT')
            require(loop_backing(s['loop'],image)==s.get('loop_rdev'),'LOOP_DEVICE_CHANGED')
            command(['losetup','--detach',s['loop']],timeout=10)
    else:
        require(mount_source(mount) is None,'UNKNOWN_MOUNT')
        attached=command(['losetup','--noheadings','--associated',str(image),'--output','NAME'])
        require(not attached,'UNKNOWN_LOOP_ATTACHMENT')
    require(not os.listdir(mount),'MOUNT_DIRECTORY_NOT_EMPTY')
    os.rmdir(mount)
    image_identity(s,run)
    os.unlink(image)
    require(not os.listdir(run),'RUN_NOT_EMPTY')
    os.rmdir(run)
    os.unlink(STATE,dir_fd=dfd);os.fsync(dfd)


def reset(expected_run_id=None):
    guard()
    if not os.path.lexists(BASE):
        require(expected_run_id is None,'RUN_ID_MISMATCH')
        print(json.dumps({'status':'ALREADY_CLEAN'}));return 0
    with locked() as dfd:
        s=read_state(dfd)
        if s is None:
            require(expected_run_id is None,'RUN_ID_MISMATCH')
            require(set(os.listdir(BASE))=={LOCK},'ORPHAN_RESOURCES')
            print(json.dumps({'status':'ALREADY_CLEAN'}));return 0
        if expected_run_id is not None: require(s['run_id']==expected_run_id,'RUN_ID_MISMATCH')
        reset_locked(dfd,s)
        print(json.dumps({'status':'CLEANUP_PASS','run_id':s['run_id']}));return 0


def inject(cli_receipt=False):
    guard()
    with locked() as dfd:
        require(read_state(dfd) is None and set(os.listdir(BASE))=={LOCK},'PREVIOUS_RUN_OR_ORPHAN')
        require(os.statvfs(LAB).f_bavail*os.statvfs(LAB).f_frsize>=5*1024**3,'FREE_SPACE_LOW')
        rid=secrets.token_hex(12);run=BASE/rid
        os.mkdir(run,0o700);st=directory(run)
        s={'version':1,'mode':'inode','run_id':rid,'phase':'STARTING','run_dev':st.st_dev,'run_ino':st.st_ino}
        write_state(dfd,s)
        try:
            mount=run/'mount';os.mkdir(mount,0o700)
            fd=os.open(run/'disk.img',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            try:
                os.ftruncate(fd,IMAGE_SIZE);os.fsync(fd);img=os.fstat(fd)
            finally:os.close(fd)
            s.update(phase='IMAGE_READY',image_dev=img.st_dev,image_ino=img.st_ino);write_state(dfd,s)
            image=image_identity(s,run)
            command(['mkfs.ext4','-q','-F','-N','1024',str(image)],timeout=30)
            image_identity(s,run)
            loop=command(['losetup','--find','--show','--nooverlap',str(image)],timeout=10)
            require(bool(LOOP.fullmatch(loop)),'BAD_LOOP_RETURN')
            s.update(loop=loop,loop_rdev=loop_backing(loop,image),phase='LOOP_READY');write_state(dfd,s)
            command(['mount','-t','ext4','-o','nosuid,nodev,noexec',loop,str(mount)],timeout=10)
            s['phase']='MOUNTED';write_state(dfd,s)
            _,_,mounted=verify_mount(s,run);require(mounted,'MOUNT_FAILED')
            exhausted=False
            for i in range(FILE_LIMIT):
                try:
                    fd=os.open(mount/('inode-%04d'%i),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                    os.close(fd)
                except OSError as e:
                    if e.errno==errno.ENOSPC: exhausted=True;break
                    raise
            require(exhausted and os.statvfs(mount).f_ffree==0,'INODE_EXHAUSTION_NOT_OBSERVED')
            check_contents(mount)
            s.update(phase='FAULT',file_count=i);write_state(dfd,s)
            result = {'receipt':'L01_INODE_OWNER_V1','run_id':rid} if cli_receipt else \
                     {'status':'INODE_FAULT_PRESENT','run_id':rid,'created_files':i,'free_inodes':0}
            print(json.dumps(result))
            return 0
        except Exception:
            # Only a completely identified image and device may be cleaned.
            try:
                if 'image_ino' in s:reset_locked(dfd,s)
            except Exception:
                print('L01: preserving resources requiring inspection',file=sys.stderr)
            raise


def verify_owner(rid):
    guard()
    require(isinstance(rid,str) and RID.fullmatch(rid),'BAD_RUN_ID')
    with locked() as dfd:
        s=read_state(dfd)
        require(s is not None and s['run_id']==rid and s['phase']=='FAULT','RUN_ID_MISMATCH')
        run=run_path(s)
        _,_,mounted=verify_mount(s,run)
        require(mounted,'MOUNT_MISSING')
    print(json.dumps({'status':'OWNER_VERIFIED','run_id':rid}))
    return 0


def main(argv):
    require(len(argv)>=2,'USAGE')
    if argv[1]=='inject':
        require(len(argv)==2 or argv[2:]==['--cli'],'USAGE')
        return inject(len(argv)==3)
    if argv[1]=='verify-owner':
        require(len(argv)==3,'USAGE')
        return verify_owner(argv[2])
    if argv[1]=='inspect-clean':
        require(len(argv)==2,'USAGE')
        return inspect_clean()
    require(argv[1] in ('check','reset') and len(argv) in (2,3),'USAGE')
    rid=argv[2] if len(argv)==3 else None
    if rid is not None: require(bool(RID.fullmatch(rid)),'BAD_RUN_ID')
    return {'check':check,'reset':reset}[argv[1]](rid)


if __name__=='__main__':
    try:sys.exit(main(sys.argv))
    except (Refused,OSError,ValueError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status':'FAIL_CLOSED','error':str(exc) if isinstance(exc,Refused) else type(exc).__name__}),file=sys.stderr)
        sys.exit(2)
