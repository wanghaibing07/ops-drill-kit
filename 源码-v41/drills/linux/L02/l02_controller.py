"""L02 transactional orchestration; platform adapter intentionally supplied separately.

No shell commands, filesystem access, or service changes are performed here.
A production backend MUST satisfy the contract in README.md. Persist operations
must be durable and serialized under one exclusive controller lock.
"""
from dataclasses import dataclass
import re
import secrets
from l02_policy import Refused, require, preflight, recovered, reset_decision

RID = re.compile(r'^[0-9a-f]{24}$')
SHA = re.compile(r'^[0-9a-f]{64}$')

@dataclass(frozen=True)
class Snapshot:
    run_id: str
    port: int
    original_digest: str
    fault_digest: str
    phase: str

    def validate(self):
        require(RID.fullmatch(self.run_id) is not None, 'bad run id')
        require(type(self.port) is int and 1024 <= self.port <= 65535, 'bad port')
        require(SHA.fullmatch(self.original_digest) is not None and SHA.fullmatch(self.fault_digest) is not None, 'bad digest')
        require(self.original_digest != self.fault_digest, 'unchanged fault config')
        require(self.phase in ('PREPARED', 'CONFIG_REQUESTED', 'FAULT', 'RESETTING', 'RESTORED'), 'bad phase')


def save_phase(backend, state, phase):
    state = Snapshot(state.run_id, state.port, state.original_digest, state.fault_digest, phase)
    backend.save_durable(state)
    return state


def start(backend, port):
    """Must be called with backend's exclusive lock held throughout this call."""
    require(backend.load() is None, 'run already exists')
    require(backend.no_orphans(), 'orphan resources')
    require(type(port) is int and 1024 <= port <= 65535, 'bad port')
    # backend prepares no mutable system objects. The watchdog must be armed
    # only after durable PREPARED exists; preflight itself verifies this.
    original, fault = backend.prepare_config(port)
    state = Snapshot(secrets.token_hex(12), port, original, fault, 'PREPARED')
    state.validate()
    backend.save_durable(state)
    try:
        backend.arm_watchdog(state)
        observation = backend.observe(state)
        preflight(observation)
        require(observation.config_digest == state.original_digest, 'baseline configuration changed')
        # Persist intent first: reset must be safe if interruption occurs at
        # any instruction around the following compare-and-swap.
        state = save_phase(backend, state, 'CONFIG_REQUESTED')
        backend.install_fault_config_if_original(state)
        # Revalidate port and policy immediately before service action.
        backend.verify_fault_prerequisites(state)
        backend.restart_owned_service(state)
        require(backend.observe_expected_denial(state), 'expected SELinux denial absent')
        state = save_phase(backend, state, 'FAULT')
        return state.run_id
    except Exception:
        # Retain transaction and watchdog; no assumptions about partial writes.
        backend.record_failure(state)
        raise


def check(backend, run_id):
    state = backend.load()
    require(state is not None, 'no active run')
    state.validate()
    require(state.run_id == run_id and state.phase == 'FAULT', 'run is not active')
    require(backend.verify_injection_evidence(state), 'missing owned denial evidence')
    observation = backend.observe(state)
    status, active, listener, config_ok = backend.recovery_observation(state)
    return recovered(observation, state.fault_digest, status, active, listener, config_ok)


def reset(backend, run_id):
    state = backend.load()
    if state is None:
        require(backend.clean_and_healthy(), 'unowned or unhealthy resources')
        return
    state.validate()
    require(state.run_id == run_id, 'run id mismatch')
    # All resources are checked before any mutation. Each subsequent mutation
    # must independently recheck ownership with compare-and-swap semantics.
    digest, mapping, mapping_owned, original_mapping, healthy = backend.reset_observation(state)
    actions = reset_decision(digest, state.original_digest, state.fault_digest,
                             mapping, mapping_owned, original_mapping, healthy)
    state = save_phase(backend, state, 'RESETTING')
    try:
        if 'restore_owned_config' in actions:
            backend.restore_config_if_fault(state)
        if 'remove_owned_mapping' in actions:
            backend.remove_owned_mapping_if_unchanged(state)
        if 'verify_or_recover_owned_service' in actions:
            backend.recover_owned_service(state)
        require(backend.verify_baseline(state), 'baseline verification failed')
        state = save_phase(backend, state, 'RESTORED')
        backend.cancel_owned_watchdog(state)
        require(backend.verify_cleanup(state), 'cleanup verification failed')
        backend.finish_durable(state)
    except Exception:
        backend.record_failure(state)
        raise
