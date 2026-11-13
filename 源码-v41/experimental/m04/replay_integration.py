from contextlib import ExitStack
import os
import stat
import m04_controller as ctl
import m04_replay_account
import sealed_replay


def audited_restricted_replay(rid, directory, state, binlog_bytes, replay_path, start, stop, end,
                              contract, update_id, old_amount, delete_id, trusted_delete_row):
    """Review-only integration: caller supplies independently trusted row and contract.

    This is not a business entry point. The caller must hold the run lock and
    validate provenance of the expected delete row and order contract.
    """
    ctl.require(isinstance(trusted_delete_row, list) and len(trusted_delete_row) == 9 and
                all(isinstance(value, str) for value in trusted_delete_row), 'invalid trusted deleted row')
    fd = os.open(replay_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        ctl.require(stat.S_ISREG(os.fstat(fd).st_mode), 'replay source is not a regular file')
        with ExitStack() as stack:
            stream = stack.enter_context(sealed_replay.audited_replay_stream(
                fd, binlog_bytes, start, stop, end, contract, update_id, old_amount,
                delete_id, trusted_delete_row))
            account = stack.enter_context(m04_replay_account.replay_account(rid, directory, state))
            account.apply(stream)
    finally:
        os.close(fd)
