"""Bound L02 lifecycle over a fail-closed backend.

Caller serializes each entire operation with a controller lock. Backend must
supply authenticated observations and durable writes; see README before use.
No host backend that mutates SELinux policy is provided.
"""
from dataclasses import dataclass, replace
import re
from l02_policy import Refused, require
from l02_audit import verify_denial
from l02_selinux_ownership import authorize_add, prove_after_add, authorize_delete

@dataclass(frozen=True)
class Run:
    run_id: str
    port: int
    phase: str
    boot_id: str
    invocation: str
    pid: int
    started: int
    target_type: str

    def validate(self):
        require(re.fullmatch(r'[0-9a-f]{24}',self.run_id or '') is not None, 'bad run id')
        require(type(self.port) is int and 1024<=self.port<=65535, 'bad port')
        require(self.phase in ('FAULT_PENDING','FAULT','ADD_INTENT','RESOLVED','REMOVE_INTENT','RESTORED'), 'bad phase')
        require(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',self.boot_id or '') is not None, 'bad boot id')
        require(re.fullmatch(r'[0-9a-f]{32}',self.invocation or '') is not None, 'bad invocation')
        require(type(self.pid) is int and self.pid>0 and type(self.started) is int and self.started>0, 'bad process identity')
        require(re.fullmatch(r'[a-zA-Z0-9_]+_t',self.target_type or '') is not None, 'bad target type')


def get_run(b,run_id,phases):
    run=b.load_run()
    require(run is not None, 'no run')
    run.validate()
    require(run.run_id==run_id and run.phase in phases, 'run or phase mismatch')
    require(b.boot_id()==run.boot_id, 'boot changed')
    require(b.guard(), 'guard failed')
    return run


def verify_fault(b,run_id):
    run=get_run(b,run_id,('FAULT_PENDING',))
    require(b.service_identity(run),'service identity mismatch')
    # The trusted backend bounds log input and confirms PID start identity.
    require(b.pid_identity(run),'pid identity mismatch')
    event=verify_denial(b.audit_records(run),min_seconds=run.started,
                        max_seconds=b.now_seconds(),pid=run.pid,
                        executable='/usr/sbin/nginx',port=run.port,
                        expected_target_type=run.target_type)
    b.save_fault_durable(replace(run,phase='FAULT'),event)
    return event


def resolve(b,run_id):
    run=get_run(b,run_id,('FAULT',))
    require(b.watchdog_armed(run) and b.service_identity(run),'unit or watchdog mismatch')
    require(b.policy_lock_proven(),'policy transaction lock not proven')
    intent=b.mapping_intent(run)
    require(intent.run_id==run_id and intent.port==run.port,'intent identity mismatch')
    effective,local=b.policy_snapshot()
    authorize_add(intent,effective,local)
    b.save_intent_durable(replace(run,phase='ADD_INTENT'),intent)
    b.add_mapping_once(intent)
    effective,after=b.policy_snapshot()
    require(b.effective_mapping_correct(intent,effective),'effective policy mismatch')
    receipt=prove_after_add(intent,after,True,b.policy_lock_proven())
    b.save_receipt_durable(replace(run,phase='RESOLVED'),intent,receipt)
    b.restart_owned_service(run)
    return receipt


def check(b,run_id):
    run=get_run(b,run_id,('RESOLVED',))
    require(b.verify_fault_record(run),'fault evidence missing')
    require(b.service_identity(run) and b.watchdog_armed(run),'service or watchdog mismatch')
    require(b.mapping_receipt_valid(run),'mapping receipt invalid')
    return bool(b.enforcing() and b.config_valid(run) and b.local_listener_owned(run) and
                b.http_health_ok(run))


def reset(b,run_id):
    run=b.load_run()
    if run is None:
        require(b.clean_owned_resources(run_id),'ambiguous unowned resources')
        return
    run=get_run(b,run_id,('FAULT_PENDING','FAULT','ADD_INTENT','RESOLVED','REMOVE_INTENT','RESTORED'))
    if run.phase in ('ADD_INTENT','REMOVE_INTENT'):
        # An interrupted mutation may have succeeded; never infer ownership.
        raise Refused('ambiguous policy mutation; retain evidence')
    if run.phase=='RESOLVED':
        require(b.policy_lock_proven(),'policy transaction lock not proven')
        intent,receipt=b.load_receipt(run)
        require(intent.run_id==run_id and intent.port==run.port,'receipt identity mismatch')
        _,local=b.policy_snapshot()
        authorize_delete(intent,local,receipt,b.policy_lock_proven())
        b.save_remove_intent_durable(replace(run,phase='REMOVE_INTENT'))
        b.delete_mapping_once(intent)
        _,after=b.policy_snapshot()
        require(after==intent.before,'policy restoration mismatch')
        run=replace(run,phase='RESTORED')
        b.save_restored_durable(run)
    b.stop_owned_service(run)
    require(b.verify_cleanup(run),'owned resources remain')
    b.finish_durable(run)
