"""Run-bound SELinux resolve orchestration, platform-independent backend.

An adapter must hold the same external SELinux policy transaction lock for the
entire call, not merely an application flock. No system adapter is included.
"""
from l02_policy import require
from l02_selinux_ownership import authorize_add, prove_after_add


def resolve(backend, run_id):
    """Call with controller lock and demonstrable global policy lock held."""
    require(backend.policy_transaction_lock_proven(), 'global policy lock not proven')
    state=backend.load_run()
    require(state is not None and state.run_id==run_id and state.phase=='FAULT', 'run not active')
    state.validate()
    require(backend.verify_watchdog(state), 'watchdog not armed')
    require(backend.verify_owned_service(state), 'service ownership invalid')
    require(backend.verify_injection_evidence(state), 'fault evidence invalid')
    intent=backend.make_mapping_intent(state)
    require(intent.run_id==run_id and intent.port==state.port,'mapping identity mismatch')
    effective, before=backend.policy_snapshot()
    authorize_add(intent,effective,before)
    # Durable intent precedes the sole mutation. A crash before a durable
    # receipt is deliberately ambiguous even if a matching rule appears.
    backend.save_mapping_intent_durable(state,intent)
    backend.add_http_port_once(state,intent)
    effective_after, local_after=backend.policy_snapshot()
    require(backend.effective_is_exact_owned_http(effective_after,intent), 'effective policy mismatch')
    receipt=prove_after_add(intent,local_after,True,backend.policy_transaction_lock_proven())
    backend.save_mapping_receipt_durable(state,intent,receipt)
    backend.restart_owned_service(state)
    require(backend.verify_recovery(state), 'recovery verification failed')
    return receipt
