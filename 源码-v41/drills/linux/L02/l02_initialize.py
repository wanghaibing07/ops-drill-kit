"""Collect journal/audit records and initialize a previously prepared L02 run.

The protected PREPARED record must have been durably written before starting
the transient unit. This module does not create or start a run/watchdog.
"""
import hashlib
import json
import re
import time
from pathlib import Path
from l02_policy import require, parse_ports, port_type
from l02_linux_journal import Journal,unique
from l02_isolated import properties,verify_unit,config_for
from l02_config_lifecycle import ConfigRun
from l02_journal_avc import correlate
from l02_linux_evidence import run_checked


def invocation_id(rid):
    unit='opsdrill-l02-'+rid+'.service'
    output=run_checked(['/usr/bin/systemctl','show',unit,'--no-pager','--property=InvocationID'])
    match=re.fullmatch(r'InvocationID=([0-9a-f]{32})\s*',output)
    require(match is not None,'unit invocation unavailable')
    return match.group(1)


def initialize(journal,rid,verify_watchdog):
    """Caller holds journal lock and has already enforced VM/root/SELinux guard."""
    state=journal.read(rid)
    require(state is not None and state.get('phase')=='PREPARED' and state.get('kind')=='config-port-v1', 'no prepared run')
    raw=state.get('config_run')
    require(isinstance(raw,dict) and set(raw)==set(ConfigRun.__dataclass_fields__),'bad config run')
    config=ConfigRun(**raw); config.validate()
    require(config.run_id==rid and config.phase=='FAULT','bad prepared config')
    require(config.original_sha==config.fixed_sha==hashlib.sha256(config_for(rid,config.good_port)).hexdigest() and
            config.fault_sha==hashlib.sha256(config_for(rid,config.fault_port)).hexdigest(),'bad config hashes')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    require(state.get('boot_id')==boot,'boot changed')
    begun=state.get('started_epoch'); now=int(time.time())
    require(type(begun) is int and 0<=now-begun<=120,'prepared time outside capture window')
    require(verify_unit(rid,properties(rid)),'unit identity unavailable')
    invocation=invocation_id(rid)
    require(callable(verify_watchdog) and verify_watchdog(rid,state),'no authenticated rollback watchdog')
    unit='opsdrill-l02-'+rid+'.service'
    output=run_checked(['/usr/bin/journalctl','--boot','--unit',unit,'--output=json','--no-pager'],limit=4*1024*1024)
    records=[]
    for line in output.splitlines():
        try: item=json.loads(line,object_pairs_hook=unique)
        except (ValueError,TypeError): continue
        records.append(item)
    audit=run_checked(['/usr/sbin/ausearch','--input-logs','--raw','-m','AVC','-ts','boot'],limit=4*1024*1024)
    policy=parse_ports(run_checked(['/usr/sbin/semanage','port','-l']))
    fault_type=port_type(policy,config.fault_port)
    require(fault_type=='unreserved_port_t','fault port policy changed')
    proof=correlate(records,audit.splitlines(),run_id=rid,boot_id=boot.replace('-',''),
                    invocation=invocation,port=config.fault_port,started_epoch=begun,ended_epoch=now,
                    target_type=fault_type,allow_journal_port=True)
    out=dict(state); out['phase']='FAULT'; out['fault_proof']=proof
    journal.save(rid,out)
    return proof
