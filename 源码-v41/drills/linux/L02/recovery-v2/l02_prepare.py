"""Prepare a config-only L02 run before spawning its isolated Nginx.

Experimental wiring: requires a separately installed root-controlled helper.
Errors preserve protected state; this module is not yet a deployed CLI.
"""
from dataclasses import asdict
import hashlib
from pathlib import Path
import secrets
import time
from l02_policy import require
from l02_config_lifecycle import ConfigRun
from l02_linux_inspect import inspect
from l02_linux_journal import Journal
from l02_isolated import start,config_for,properties,verify_unit
from l02_initialize import initialize,invocation_id
from l02_watchdog_arm import arm,verify_armed


def prepare(fault_port,good_port):
    require(type(fault_port) is int and type(good_port) is int and fault_port!=good_port,'invalid ports')
    fault=inspect(fault_port); good=inspect(good_port)
    require(fault['effective_listed_type']=='unreserved_port_t' and fault['local_listed_type'] is None and
            not fault['tcp_socket_present'],'fault port is not isolated and available')
    require(good['effective_listed_type']=='http_port_t' and not good['tcp_socket_present'],
            'repair port is not allowed and available')
    rid=secrets.token_hex(12)
    launch_token=secrets.token_hex(16)
    original=hashlib.sha256(config_for(rid,good_port)).hexdigest()
    injected=hashlib.sha256(config_for(rid,fault_port)).hexdigest()
    config=ConfigRun(rid,fault_port,good_port,'FAULT',original,injected,original)
    config.validate()
    boot=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    state={'version':1,'run_id':rid,'phase':'PREPARED','kind':'config-port-v1',
           'boot_id':boot,'started_epoch':int(time.time()),'config_run':asdict(config)}
    journal=Journal(create=True)
    try:
        with journal.locked():
            require(journal.read(rid) is None,'run already exists')
            journal.save(rid,state)
            state=arm(journal,state)
            def before_spawn(expected):
                nonlocal state
                current=journal.read(rid)
                require(expected==rid and current==state and current['phase']=='PREPARED','prepared state changed')
                verify_armed(current)
                state=dict(current,launch_intent={'version':1,'token':launch_token})
                journal.save(rid,state)
            require(start(fault_port,rid=rid,before_spawn=before_spawn,launch_token=launch_token)==rid,'run identity changed')
            props=properties(rid)
            require(verify_unit(rid,props,launch_token),'unit identity missing')
            observed=invocation_id(rid)
            require(observed!='0'*32 and verify_unit(rid,properties(rid),launch_token) and
                    invocation_id(rid)==observed,'unit identity changed during capture')
            state=dict(state); state['invocation']=observed
            journal.save(rid,state)
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                props=properties(rid)
                require(verify_unit(rid,props,launch_token) and invocation_id(rid)==observed,'unit identity changed')
                if props.get('ActiveState')=='failed': break
                time.sleep(.2)
            else: raise RuntimeError('fault unit did not fail before deadline')
            initialize(journal,rid,lambda expected,record: expected==rid and verify_armed(record))
            return rid
    finally: journal.close()
