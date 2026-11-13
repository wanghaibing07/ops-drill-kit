#!/usr/bin/env python3
"""Experimental L02 Linux CLI; not installed or validated end to end.

Root-owned helper installation, recovery races and full lifecycle still need
independent review and isolated-VM contract testing before deployment.
"""
import argparse
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
from l02_policy import Refused, require
from l02_linux_inspect import secure_marker
from l02_isolated import start,cleanup,command,ROOT
from l02_linux_journal import Journal
from l02_linux_config_backend import LinuxConfigBackend
from l02_config_lifecycle import check, repair, reset


def guard():
    require(os.geteuid()==0,'root required')
    secure_marker()
    require(command('/usr/bin/systemd-detect-virt','--vm').stdout.strip()=='vmware','not VMware')
    require(command('/usr/sbin/getenforce').stdout.strip()=='Enforcing','SELinux not Enforcing')


def inspect_clean():
    def check_lock(dirfd):
        try: fd=os.open('.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dirfd)
        except FileNotFoundError: return
        try:
            st=os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
                    stat.S_IMODE(st.st_mode)==0o600,'unsafe L02 lock')
        finally: os.close(fd)
    journal_path=Path('/var/lib/opsdrill/l02-journal')
    if os.path.lexists(journal_path):
        j=Journal(create=False)
        try:
            require(set(os.listdir(j.fd)) <= {'.lock'},'L02 journal contains retained state')
            check_lock(j.fd)
        finally: j.close()
    if os.path.lexists(ROOT):
        st=ROOT.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,'unsafe L02 config directory')
        require(set(os.listdir(ROOT)) <= {'.lock'},'L02 config directory contains retained state')
        fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try: check_lock(fd)
        finally: os.close(fd)
    require(not list(Path('/run').glob('opsdrill-l02-*.pid')),'L02 PID file present')
    output=command('/usr/bin/systemctl','list-units','--all','--plain','--no-legend','opsdrill-l02-*').stdout
    require(not output.strip(),'L02 transient units remain')
    print('L02 clean')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='action',required=True)
    start_full=commands.add_parser('start'); start_full.add_argument('fault_port',type=int,nargs='?',default=19081); start_full.add_argument('good_port',type=int,nargs='?',default=8443)
    start_p=commands.add_parser('start-isolated'); start_p.add_argument('port',type=int)
    cleanup_p=commands.add_parser('stop-isolated'); cleanup_p.add_argument('run_id')
    journal_p=commands.add_parser('journal'); journal_p.add_argument('run_id')
    commands.add_parser('journal-list')
    commands.add_parser('inspect-clean')
    for name in ('check','resolve','reset','verify-owner'):
        item=commands.add_parser(name); item.add_argument('run_id')
    args=parser.parse_args(argv)
    guard()
    if args.action=='inspect-clean':
        inspect_clean(); return 0
    if args.action=='start':
        from l02_prepare import prepare
        rid=prepare(args.fault_port,args.good_port)
        print(json.dumps({'receipt':'L02_CONFIG_OWNER_V1','run_id':rid,
                          'timer':'opsdrill-l02-recover-'+rid+'.timer'})); return 0
    if args.action=='start-isolated':
        print(start(args.port)); return 0
    if args.action=='stop-isolated':
        cleanup(args.run_id); return 0
    if args.action in ('journal','journal-list'):
        j=Journal(create=False)
        try:
            # Read is protected by root-only state directory; a lock file is
            # deliberately not created during read-only inspection.
            def summary(state):
                result={'run_id':state['run_id'],'phase':state['phase']}
                if state.get('phase')=='PREPARED' and state.get('invocation') is None:
                    result['review']='START_INCOMPLETE_IDENTITY_MAY_BE_UNVERIFIED'
                elif state.get('phase')=='NEEDS_REVIEW':
                    result['review']='MANUAL_REVIEW_REQUIRED'
                    if state.get('watchdog_status') in ('IDENTITY_UNVERIFIED','STOPPED_OR_ABSENT'):
                        result['watchdog_status']=state['watchdog_status']
                return result
            if args.action=='journal-list':
                names=os.listdir(j.fd)
                ids=sorted(name[:-5] for name in names if re.fullmatch(r'[0-9a-f]{24}\.json',name))
                records=[j.read(rid) for rid in ids]
                require(all(record is not None for record in records),'journal changed during listing')
                print(json.dumps([summary(record) for record in records],sort_keys=True))
            else:
                state=j.read(args.run_id)
                require(state is not None,'journal not found')
                print(json.dumps(summary(state),sort_keys=True))
        finally: j.close()
        return 0
    backend=LinuxConfigBackend(args.run_id)
    try:
        with backend.journal.locked():
            if args.action=='reset':
                record=backend.journal.read(args.run_id)
                if record is not None and record.get('phase')=='NEEDS_REVIEW':
                    backend.reconcile_watchdog()
            state=backend.load()
            if args.action=='reset':
                reset(backend,args.run_id); return 0
            require(state is not None,'no protected run state')
            require(backend.watchdog_armed(state),'independent rollback watchdog not armed')
            if args.action=='verify-owner':
                require(state.phase=='FAULT' and backend.fault_present(state),'fault ownership not verified')
                print('L02 owner verified'); return 0
            if args.action=='check':
                if state.phase=='FAULT':
                    require(backend.fault_present(state),'fault evidence or identity changed')
                    print('L02 fault confirmed'); return 1
                if check(backend,args.run_id): print('PASS'); return 0
                print('L02 recovery check failed'); return 1
            if args.action=='resolve':
                repair(backend,args.run_id); return 0
    finally: backend.close()

if __name__=='__main__':
    try: sys.exit(main())
    except (Refused,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print('l02: '+str(exc),file=sys.stderr); sys.exit(2)
