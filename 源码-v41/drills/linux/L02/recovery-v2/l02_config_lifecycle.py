"""Config-only L02 lifecycle. No SELinux policy changes.

Caller holds controller lock for the whole call and backend methods are trusted,
root-protected and durable. Production backend remains a separate requirement.
"""
from dataclasses import dataclass, replace
import hashlib
import re
from l02_policy import Refused, require, port_type

@dataclass(frozen=True)
class ConfigRun:
    run_id: str
    fault_port: int
    good_port: int
    phase: str
    original_sha: str
    fault_sha: str
    fixed_sha: str

    def validate(self):
        require(re.fullmatch(r'[0-9a-f]{24}',self.run_id or '') is not None,'bad run id')
        require(type(self.fault_port) is int and type(self.good_port) is int and
                1024<=self.fault_port<=65535 and 1024<=self.good_port<=65535 and
                self.fault_port!=self.good_port,'bad ports')
        require(self.phase in ('FAULT','REPAIR_INTENT','REPAIRED','RESET_INTENT','RESTORED'),'bad phase')
        require(all(re.fullmatch(r'[0-9a-f]{64}',x or '') for x in
                    (self.original_sha,self.fault_sha,self.fixed_sha)),'bad digest')
        require(self.fault_sha != self.original_sha and self.fault_sha != self.fixed_sha,'fault config unchanged')


def require_active(backend, run_id, phases, allow_absent=False):
    state=backend.load()
    require(state is not None,'no active run')
    state.validate()
    require(state.run_id==run_id and state.phase in phases,'run or phase mismatch')
    require(backend.guard() and backend.same_boot(state),'guard or boot mismatch')
    require(backend.service_identity(state) or (allow_absent and backend.service_absent(state)),'unowned service')
    return state


def repair(backend, run_id):
    state=require_active(backend,run_id,('FAULT',))
    require(backend.verify_fault_evidence(state),'unproven AVC')
    require(backend.watchdog_armed(state),'watchdog not armed')
    effective,local=backend.port_snapshots()
    require(port_type(effective,state.good_port)=='http_port_t','repair port not allowed by SELinux')
    require(backend.port_available(state.good_port),'repair port busy')
    require(backend.config_digest(state)==state.fault_sha,'fault configuration changed')
    # This transaction does not modify SELinux; snapshots are compared after
    # service actions so drift is surfaced even though external races exist.
    backend.save(replace(state,phase='REPAIR_INTENT'))
    backend.replace_owned_config(state,state.fault_sha,state.fixed_sha)
    require(backend.watchdog_armed(state),'watchdog lost')
    require(backend.port_available(state.good_port),'repair port became busy')
    backend.restart_owned_service(state)
    require(backend.port_snapshots()==(effective,local),'SELinux policy drift')
    require(backend.health(state,state.good_port),'repair failed health check')
    backend.save(replace(state,phase='REPAIRED'))


def check(backend,run_id):
    state=require_active(backend,run_id,('REPAIRED',))
    effective,_=backend.port_snapshots()
    return bool(backend.verify_fault_evidence(state) and backend.watchdog_armed(state) and
                port_type(effective,state.good_port)=='http_port_t' and
                backend.config_digest(state)==state.fixed_sha and backend.health(state,state.good_port))


def reset(backend,run_id):
    state=backend.load()
    if state is None:
        require(backend.clean(run_id),'unowned resources or unhealthy state')
        return
    state=require_active(backend,run_id,('FAULT','REPAIR_INTENT','REPAIRED','RESET_INTENT','RESTORED'),allow_absent=True)
    digest=backend.config_digest(state)
    require(digest in (state.original_sha,state.fault_sha,state.fixed_sha),'foreign config change')
    # Persist before mutation; the backend uses atomic compare-and-swap with a
    # root-only directory and verifies the recorded exact inode and contents.
    backend.save(replace(state,phase='RESET_INTENT'))
    if digest!=state.original_sha:
        backend.replace_owned_config(state,digest,state.original_sha)
    backend.stop_owned_service(state)
    require(backend.verify_restored(state),'restoration verification failed')
    backend.save(replace(state,phase='RESTORED'))
    backend.cancel_owned_watchdog(state)
    require(backend.verify_cleanup(state),'owned resource cleanup failed')
    backend.finish(state)
