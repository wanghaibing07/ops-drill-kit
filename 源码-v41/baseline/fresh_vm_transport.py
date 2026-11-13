#!/usr/bin/env python3
"""Transport a separately pinned ops-drill-kit package to an identified lab VM.

Requires a pre-provisioned VMware guest, devops SSH public-key access and
passwordless sudo. The operator obtains the host-key fingerprint, VM UUID and
package SHA256 values independently. Upload/staging never replace destinations.
Failed state and inboxes are retained. No VM, snapshot or disk is created.
"""
import argparse, base64, hashlib, hmac, ipaddress, re, secrets, select, shlex, socket, subprocess, sys, time, uuid
from pathlib import Path
import paramiko

FILES=('source.tar.gz','extract.py','stage.py')
PROTECTED_VMX=Path(r'D:\vm\od-lab\od-lab.vmx')

def validate_package(args):
    payload={}
    for name,expected in zip(FILES,(args.bundle_sha,args.extract_sha,args.stage_sha)):
        if not re.fullmatch(r'[0-9a-f]{64}',expected): raise ValueError('invalid package digest')
        p=args.package/name
        if not p.is_file() or p.is_symlink():raise ValueError('unsafe package input: '+name)
        raw=p.read_bytes()
        if len(raw)>20000000 or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('package digest mismatch: '+name)
        payload[name]=raw
    return payload

def validate_vm(args):
    vmx=args.vmx.resolve(strict=True)
    if vmx.suffix.lower()!='.vmx' or str(vmx).lower()==str(PROTECTED_VMX).lower():raise ValueError('invalid or protected VM')
    rows=subprocess.run([str(args.vmrun),'list'],capture_output=True,text=True,timeout=15,check=True).stdout.splitlines()[1:]
    if str(vmx).lower() not in [x.strip().lower() for x in rows]:raise ValueError('VM not running')
    settings={}
    for line in vmx.read_text(encoding='utf-8-sig').splitlines():
        match=re.fullmatch(r'\s*([^#\s=]+)\s*=\s*"([^"\r\n]*)"\s*',line)
        if match:
            key=match.group(1).lower()
            if key in settings:raise ValueError('duplicate VMX setting')
            settings[key]=match.group(2)
    raw=re.sub(r'[^0-9a-f]','',settings.get('uuid.bios','').lower())
    if not re.fullmatch('[0-9a-f]{32}',raw):raise ValueError('invalid VM UUID')
    actual=str(uuid.UUID(bytes_le=bytes.fromhex(raw)))
    if actual!=args.dmi:raise ValueError('VM UUID mismatch')
    ip=ipaddress.ip_address(args.ip)
    if not ip.is_private or ip.is_loopback or ip.is_unspecified:raise ValueError('lab IP required')
    if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',args.host_key):raise ValueError('invalid host key fingerprint')

def execute(client, command, data=b'', limit=120):
    channel=client.get_transport().open_session(timeout=15);channel.exec_command(command)
    if data:channel.sendall(data)
    channel.shutdown_write(); start=time.monotonic();size=0
    while True:
        for ready,recv,stream in ((channel.recv_ready,channel.recv,sys.stdout),(channel.recv_stderr_ready,channel.recv_stderr,sys.stderr)):
            if ready():
                raw=recv(65536);size+=len(raw)
                if size>1000000:raise RuntimeError('output limit exceeded; inspect remote state before retry')
                stream.write(raw.decode('utf8','replace'));stream.flush()
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():break
        if time.monotonic()-start>limit:raise TimeoutError('remote outcome unknown; inspect before retry')
        select.select([channel],[],[],1)
    return channel.recv_exit_status()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vmx',type=Path,required=True);p.add_argument('--vmrun',type=Path,required=True)
    p.add_argument('--ip',required=True);p.add_argument('--dmi',required=True);p.add_argument('--host-key',required=True)
    p.add_argument('--private-key',type=Path,required=True);p.add_argument('--package',type=Path,required=True)
    p.add_argument('--bundle-sha',required=True);p.add_argument('--extract-sha',required=True);p.add_argument('--stage-sha',required=True);p.add_argument('--bootstrap-sha',required=True)
    p.add_argument('--inbox');p.add_argument('action',choices=('inspect','upload','stage-dry-run','stage-apply','bootstrap-dry-run','bootstrap-apply'))
    args=p.parse_args();payload=validate_package(args);validate_vm(args)
    if not re.fullmatch('[0-9a-f]{64}',args.bootstrap_sha):raise ValueError('invalid bootstrap digest')
    if args.action.startswith('stage-') and (not args.inbox or not re.fullmatch(r'/var/tmp/opsdrill-inbox-[0-9a-f]{16}',args.inbox)):raise ValueError('invalid inbox')
    with socket.create_connection((args.ip,22),timeout=8) as sock:
        transport=paramiko.Transport(sock)
        try:
            transport.start_client(timeout=8);key=transport.get_remote_server_key()
            fp='SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            if key.get_name()!='ssh-ed25519' or not hmac.compare_digest(fp,args.host_key):raise ValueError('SSH host key mismatch')
            transport.auth_publickey('devops',paramiko.Ed25519Key.from_private_key_file(str(args.private_key)))
            client=paramiko.SSHClient();client._transport=transport
            verify="from pathlib import Path; import sys; sys.exit(0 if Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==sys.argv[1] else 2)"
            rc=execute(client,'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(verify)+' '+shlex.quote(args.dmi),limit=20)
            if rc:raise ValueError('guest UUID mismatch')
            print('Pinned VM, SSH host key and package verified',flush=True)
            if args.action=='inspect':return 0
            if args.action=='upload':
                inbox='/var/tmp/opsdrill-inbox-'+secrets.token_hex(8);sftp=client.open_sftp()
                try:
                    sftp.mkdir(inbox,0o700)
                    for name in FILES[:2]:
                        with sftp.file(inbox+'/'+name,'wx') as dst:
                            dst.chmod(0o600)
                            dst.write(payload[name])
                finally:sftp.close()
                print('Uploaded private inbox:',inbox,flush=True);return 0
            if args.action.startswith('stage-'):
                cmd='sudo -n /usr/bin/python3 -I -B - --vm-uuid '+shlex.quote(args.dmi)+' --inbox '+shlex.quote(args.inbox)
                if args.action=='stage-apply':cmd+=' --apply'
                return execute(client,cmd,payload['stage.py'],limit=240)
            root='/usr/local/libexec/opsdrill-clean-'+args.bundle_sha[:16]
            script=root+'/baseline/bootstrap.py'
            wrapper="""import hashlib,os,stat,sys
from pathlib import Path
p=Path(sys.argv[1]); expected=sys.argv[2]
for x in (p.parent,*p.parent.parents):
 s=x.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022: sys.exit(2)
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
with os.fdopen(fd,'rb') as f:
 s=os.fstat(f.fileno()); b=f.read(1048577)
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or s.st_mode&0o022 or len(b)>1048576 or hashlib.sha256(b).hexdigest()!=expected: sys.exit(2)
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(p)]+sys.argv[3:])"""
            parts=['sudo','-n','/usr/bin/python3','-I','-B','-c',wrapper,script,args.bootstrap_sha,'--vm-uuid',args.dmi]
            if args.action=='bootstrap-apply':parts+=['--apply','--actor','agent']
            return execute(client,' '.join(shlex.quote(x) for x in parts),limit=3600)
        finally:transport.close()

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:print('Transport refused or failed:',type(exc).__name__,str(exc),file=sys.stderr);sys.exit(2)
