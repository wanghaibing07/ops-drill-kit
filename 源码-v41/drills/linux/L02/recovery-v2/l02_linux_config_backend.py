"""Linux backend for the config-only L02 lifecycle (experimental).

Mutations are limited to a pre-existing root-owned isolated run directory.
A valid independent watchdog and authenticated AVC record are mandatory; this
backend does not yet create them, so ordinary runs must fail closed.
"""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import urllib.request
import urllib.error
from l02_linux_evidence import verify_fault, verify_listener
from l02_policy import Refused, require, parse_ports
from l02_config_lifecycle import ConfigRun
from l02_linux_inspect import secure_marker, cmd, listening_tcp
from l02_linux_journal import Journal,unique
from l02_linux_config import replace_config
from l02_isolated import ROOT, config_for, locked, run_fd, read_secure, properties, verify_unit, command
from l02_watchdog_arm import verify_armed,cancel_owned
from l02_initialize import invocation_id

class LinuxConfigBackend:
    def __init__(self,run_id):
        require(re.fullmatch(r'[0-9a-f]{24}',run_id or '') is not None,'invalid run id')
        self.run_id=run_id
        self.journal=Journal(create=False)
        self.record=None

    def close(self): self.journal.close()

    def load(self):
        self.record=self.journal.read(self.run_id)
        if self.record is None: return None
        require(self.record.get('kind')=='config-port-v1','unexpected run kind')
        raw=self.record.get('config_run')
        require(isinstance(raw,dict) and set(raw)==set(ConfigRun.__dataclass_fields__),'invalid config run')
        try: state=ConfigRun(**raw); state.validate()
        except (TypeError,ValueError): raise Refused('invalid run state')
        require(state.run_id==self.run_id and state.phase==self.record['phase'],'run mismatch')
        require(self.record.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip(),'boot changed')
        require(state.original_sha==hashlib.sha256(config_for(state.run_id,state.good_port)).hexdigest() and
                state.fixed_sha==state.original_sha and
                state.fault_sha==hashlib.sha256(config_for(state.run_id,state.fault_port)).hexdigest(), 'unexpected config hashes')
        return state

    def save(self,state):
        state.validate()
        require(self.record is not None and state.run_id==self.run_id,'missing state')
        obj=dict(self.record); obj['phase']=state.phase; obj['config_run']=asdict(state)
        self.journal.save(self.run_id,obj); self.record=obj

    def guard(self):
        require(os.geteuid()==0,'root required'); secure_marker()
        return (cmd('/usr/bin/systemd-detect-virt','--vm').strip()=='vmware' and
                cmd('/usr/sbin/getenforce').strip()=='Enforcing')

    def same_boot(self,state):
        return self.record.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()

    def service_identity(self,state):
        return verify_unit(state.run_id,properties(state.run_id))

    def service_absent(self,state):
        first=properties(state.run_id); second=properties(state.run_id)
        return (first.get('LoadState')==second.get('LoadState')=='not-found' and
                not os.path.lexists('/run/opsdrill-l02-'+state.run_id+'.pid'))

    def reconcile_watchdog(self):
        record=self.journal.read(self.run_id)
        require(record is not None and record.get('phase')=='NEEDS_REVIEW' and
                record.get('watchdog_status')=='STOPPED_OR_ABSENT','no verified watchdog recovery')
        raw=record.get('config_run')
        require(isinstance(raw,dict) and set(raw)==set(ConfigRun.__dataclass_fields__),'invalid config state')
        state=ConfigRun(**raw); state.validate()
        require(state.run_id==self.run_id and record.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip(),
                'run or boot changed')
        self.record=record
        require(self.guard(),'guard failed')
        props=properties(state.run_id)
        if verify_unit(state.run_id,props):
            require(record.get('invocation')==invocation_id(state.run_id) and
                    props.get('ActiveState') in ('inactive','failed') and not props.get('ControlGroup'),
                    'service is not safely stopped')
        else:
            require(self.service_absent(state),'service identity ambiguous')
        require(self.config_digest(state) in (state.original_sha,state.fault_sha,state.fixed_sha),'config changed')
        updated=dict(record); updated['phase']=state.phase
        self.journal.save(self.run_id,updated); self.record=updated
        return state

    def _with_run(self,func):
        with locked() as rootfd:
            fd=run_fd(rootfd,self.run_id)
            try: return func(fd)
            finally: os.close(fd)

    def config_digest(self,state):
        return self._with_run(lambda fd: hashlib.sha256(read_secure(fd,'nginx.conf')).hexdigest())

    def replace_owned_config(self,state,old,new):
        target=config_for(state.run_id,state.good_port if new==state.original_sha else state.fault_port)
        require(hashlib.sha256(target).hexdigest()==new,'unknown target config')
        return self._with_run(lambda fd: replace_config(fd,'nginx.conf',old,target))

    def port_snapshots(self):
        return (parse_ports(cmd('/usr/sbin/semanage','port','-l')),
                parse_ports(cmd('/usr/sbin/semanage','port','-l','-C')))

    def port_available(self,port):
        tables=[Path('/proc/net/tcp').read_text(encoding='ascii'),Path('/proc/net/tcp6').read_text(encoding='ascii')]
        return not listening_tcp(port,tables)

    def restart_owned_service(self,state):
        require(self.service_identity(state),'unit changed')
        require(self.record.get('invocation')==invocation_id(state.run_id),'service invocation changed')
        command('/usr/bin/systemctl','restart','opsdrill-l02-'+state.run_id+'.service')
        require(self.service_identity(state),'unit changed')
        invocation=invocation_id(state.run_id)
        updated=dict(self.record); updated['invocation']=invocation
        self.journal.save(self.run_id,updated)
        self.record=updated

    def stop_owned_service(self,state):
        props=properties(state.run_id)
        if verify_unit(state.run_id,props):
            require(self.record.get('invocation')==invocation_id(state.run_id),'service invocation changed')
            if props.get('ActiveState') not in ('inactive','failed'):
                command('/usr/bin/systemctl','stop','opsdrill-l02-'+state.run_id+'.service')
            props=properties(state.run_id)
            if verify_unit(state.run_id,props):
                require(props.get('ActiveState') in ('inactive','failed') and not props.get('ControlGroup'),
                        'owned service still running')
                if props.get('ActiveState')=='failed':
                    require(self.record.get('invocation')==invocation_id(state.run_id),'service invocation changed')
                    command('/usr/bin/systemctl','reset-failed','opsdrill-l02-'+state.run_id+'.service')
                    props=properties(state.run_id)
                    if verify_unit(state.run_id,props):
                        require(props.get('ActiveState')=='inactive' and not props.get('ControlGroup'),
                                'failed service not cleared')
        require(not os.path.lexists('/run/opsdrill-l02-'+state.run_id+'.pid'),'owned PID file remains')

    def health(self,state,port):
        try:
            require(self.service_identity(state),'service identity changed')
            verify_listener(state.run_id,port)
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs): return None
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
            with opener.open('http://127.0.0.1:%d/healthz' % port,timeout=3) as response:
                return response.status==200 and response.read(64)==b'l02-isolated\n'
        except (Refused,OSError,ValueError,urllib.error.URLError): return False

    def verify_fault_evidence(self,state):
        proof=self.record.get('fault_proof')
        if isinstance(proof,dict):
            audit=proof.get('audit')
            return bool(proof.get('boot_id')==self.record.get('boot_id','').replace('-','') and
                        re.fullmatch(r'[0-9a-f]{32}',proof.get('invocation','')) and
                        type(proof.get('pid')) is int and proof['pid']>0 and
                        type(proof.get('journal_timestamp_us')) is int and
                        re.fullmatch(r'[0-9a-f]{64}',proof.get('journal_message_sha256','')) and
                        isinstance(audit,dict) and re.fullmatch(r'[0-9]+',audit.get('audit_serial','')))
        try:
            verify_fault(state.run_id,state.fault_port,self.record.get('fault_identity'))
            return True
        except (Refused,OSError,ValueError,UnicodeError,subprocess.SubprocessError): return False

    def fault_present(self,state):
        try:
            props=properties(state.run_id)
            return bool(self.guard() and verify_unit(state.run_id,props) and props.get('ActiveState')=='failed' and
                        self.record.get('invocation')==invocation_id(state.run_id) and
                        self.config_digest(state)==state.fault_sha and self.verify_fault_evidence(state) and
                        self.watchdog_armed(state))
        except (Refused,OSError,ValueError,KeyError,subprocess.SubprocessError): return False

    def watchdog_armed(self,state):
        try:
            require(getattr(self,'record',None) is not None and state is not None and
                    getattr(state,'run_id',None)==getattr(self,'run_id',None),'missing watchdog state')
            return verify_armed(self.record)
        except (Refused,OSError,ValueError,subprocess.SubprocessError): return False

    def verify_restored(self,state):
        if state is None: return False
        try:
            if not self.guard() or self.config_digest(state)!=state.original_sha: return False
            props=properties(state.run_id)
            if verify_unit(state.run_id,props):
                if (self.record.get('invocation')!=invocation_id(state.run_id) or
                    props.get('ActiveState') not in ('inactive','failed') or props.get('ControlGroup')): return False
            if os.path.lexists('/run/opsdrill-l02-'+state.run_id+'.pid'): return False
            if command('/usr/bin/systemctl','is-active','nginx',check=False).stdout.strip()!='active': return False
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self,*args,**kwargs): return None
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
            with opener.open('http://127.0.0.1:8080/health',timeout=3) as response:
                return response.status==200
        except (Refused,OSError,ValueError,KeyError,subprocess.SubprocessError,urllib.error.URLError): return False

    def cancel_owned_watchdog(self,state):
        require(getattr(self,'record',None) is not None and state is not None and
                getattr(state,'run_id',None)==getattr(self,'run_id',None),'missing watchdog state')
        return cancel_owned(self.record)

    def _verify_run_files(self,fd,state):
        require(set(os.listdir(fd))=={'nginx.conf','state.json'},'unexpected run files')
        config=read_secure(fd,'nginx.conf')
        require(hashlib.sha256(config).hexdigest()==state.original_sha,'config differs from baseline')
        state_data=read_secure(fd,'state.json')
        data=json.loads(state_data,object_pairs_hook=unique)
        require(isinstance(data,dict) and set(data)=={'run_id','port','sha256'} and data['run_id']==state.run_id and
                data['port']==state.fault_port and data['sha256']==state.fault_sha,'run metadata changed')
        return {'nginx.conf':config,'state.json':state_data}

    def verify_cleanup(self,state):
        try:
            if not self.verify_restored(state): return False
            self._with_run(lambda fd:self._verify_run_files(fd,state))
            return True
        except (Refused,OSError,ValueError,KeyError): return False

    def finish(self,state):
        require(self.record is not None and self.record.get('phase')=='RESTORED' and state.run_id==self.run_id,
                'run is not restored')
        require(self.verify_cleanup(state),'cleanup proof failed')
        with locked() as dfd:
            fd=run_fd(dfd,state.run_id)
            try:
                expected=self._verify_run_files(fd,state)
                for name in ('nginx.conf','state.json'):
                    held=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
                    try:
                        st=os.fstat(held); current=os.stat(name,dir_fd=fd,follow_symlinks=False)
                        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
                                stat.S_IMODE(st.st_mode)==0o600 and (st.st_dev,st.st_ino)==(current.st_dev,current.st_ino) and
                                os.read(held,8193)==expected[name],'run file changed before cleanup')
                        os.unlink(name,dir_fd=fd)
                    finally: os.close(held)
                os.fsync(fd)
            finally: os.close(fd)
            os.rmdir(state.run_id,dir_fd=dfd); os.fsync(dfd)
        self.journal.remove(self.run_id,self.record)
        self.record=None

    def clean(self,run_id):
        if run_id!=self.run_id: return False
        try:
            if os.path.lexists(ROOT/run_id) or os.path.lexists('/run/opsdrill-l02-'+run_id+'.pid'): return False
            if verify_unit(run_id,properties(run_id)): return False
            from l02_watchdog_arm import properties as timer_properties
            return timer_properties('opsdrill-l02-recover-'+run_id+'.timer',('LoadState',)).get('LoadState')=='not-found'
        except (Refused,OSError,ValueError,subprocess.SubprocessError): return False
