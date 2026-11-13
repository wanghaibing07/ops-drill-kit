"""Least-privilege replay account prototype; not connected to disabled business flow."""
from contextlib import contextmanager
import fcntl
import os
import re
import secrets
import subprocess
import m04_controller as ctl

# The business guard remains off. This independent guard prevents accidental
# direct use until all server-side credential exposure is reviewed.
ACCOUNT_SAFETY_READY = False

class CleanupError(RuntimeError):
    pass

def target_verified(rid, state):
    ctl.verify(rid, 'target', state['primary_uuid'], state['uuids']['target'])
    value = ctl.sql(rid, 'target', 'SELECT @@global.general_log,@@global.slow_query_log,@@global.log_bin')
    ctl.require(value == '0\t0\t0', 'general, slow and binary logging must be disabled')
    audit = ctl.sql(rid, 'target', "SELECT COUNT(*) FROM information_schema.PLUGINS "
                    "WHERE PLUGIN_TYPE='AUDIT' AND PLUGIN_STATUS='ACTIVE'")
    ctl.require(audit == '0', 'active audit plugin not permitted')
    components = ctl.sql(rid, 'target', 'SELECT COUNT(*) FROM mysql.component')
    ctl.require(components == '0', 'installed components require review')

def admin_statement(rid, state, statement):
    target_verified(rid, state)
    socket = ctl.paths(rid, 'target')[2]
    p = subprocess.run(['/usr/bin/mysql', '--no-defaults', '--protocol=SOCKET', '--socket=' + str(socket),
                        '--user=root', '--batch', '--skip-column-names'], input=statement.encode('ascii'),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, env=ctl.ENV)
    ctl.require(p.returncode == 0, 'replay account administration failed')

def account_exists(rid, state, name):
    target_verified(rid, state)
    return ctl.sql(rid, 'target', "SELECT COUNT(*) FROM mysql.user WHERE User='" + name + "' AND Host='localhost'")

class ReplayAccount:
    def __init__(self, rid, state, name, fd):
        self.rid, self.state, self.name, self.fd = rid, state, name, fd

    def apply(self, replay_fd, timeout=120):
        """Consume an already strictly audited stream from an open descriptor.

        Caller must supply the sealed descriptor produced by the audit path.
        The complete path is disabled until its VM behavior is verified.
        """
        ctl.require(ACCOUNT_SAFETY_READY, 'replay disabled pending credential exposure review')
        target_verified(self.rid, self.state)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        ctl.require(fcntl.fcntl(replay_fd, fcntl.F_GET_SEALS) & seals == seals, 'replay stream is not sealed')
        ctl.require(type(timeout) is int and 1 <= timeout <= 120, 'invalid replay timeout')
        socket = ctl.paths(self.rid, 'target')[2]
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.lseek(replay_fd, 0, os.SEEK_SET)
        result = subprocess.run(['/usr/bin/mysql', '--defaults-extra-file=/proc/self/fd/' + str(self.fd),
                                 '--protocol=SOCKET', '--socket=' + str(socket), '--user=' + self.name,
                                 '--binary-mode=1'], stdin=replay_fd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, env=ctl.ENV, pass_fds=(self.fd,))
        ctl.require(result.returncode == 0, 'restricted replay failed')

@contextmanager
def replay_account(rid, directory, state):
    """Create a one-use account, keep secret in an anonymous memfd, then drop it.

    The caller must hold the controller's per-run lock. Cleanup failure is surfaced;
    inability to verify target identity always prevents account changes.
    """
    ctl.require(ACCOUNT_SAFETY_READY, 'account provisioning disabled pending credential exposure review')
    ctl.require(hasattr(os, 'memfd_create'), 'anonymous credential storage unavailable')
    name = 'm04_' + secrets.token_hex(8)
    password = secrets.token_hex(32)
    ctl.require(re.fullmatch(r'm04_[0-9a-f]{16}', name) and re.fullmatch(r'[0-9a-f]{64}', password),
                'invalid generated credentials')
    ctl.require(account_exists(rid, state, name) == '0', 'replay account name already exists')
    ctl.require(not state.get('replay_account'), 'prior account requires cleanup')
    state['replay_account'] = {'name': name, 'status': 'CREATE_ATTEMPTED'}
    ctl.save(directory, state)
    fd = os.memfd_create('m04-replay', flags=os.MFD_CLOEXEC)
    attempted = True
    try:
        os.fchmod(fd, 0o600)
        credential = ('[client]\npassword=' + password + '\n').encode('ascii')
        offset = 0
        while offset < len(credential):
            written = os.write(fd, credential[offset:])
            ctl.require(written > 0, 'cannot write replay credentials')
            offset += written
        os.lseek(fd, 0, os.SEEK_SET)
        # Credentials are transmitted on stdin, never process arguments or logs.
        admin_statement(rid, state, "CREATE USER '" + name + "'@'localhost' IDENTIFIED BY '" + password + "';")
        password = None
        admin_statement(rid, state, "GRANT REPLICATION_APPLIER ON *.* TO '" + name + "'@'localhost';")
        admin_statement(rid, state, "GRANT UPDATE ON `orderguard_restore_m04`.`orders` TO '" + name + "'@'localhost';")
        yield ReplayAccount(rid, state, name, fd)
    finally:
        try:
            os.close(fd)
        finally:
            password = None
            if attempted:
                try:
                    admin_statement(rid, state, "DROP USER IF EXISTS '" + name + "'@'localhost';")
                    state.pop('replay_account', None)
                    ctl.save(directory, state)
                except Exception as exc:
                    raise CleanupError('replay account cleanup failed; manual inspection required') from exc


def cleanup_recorded_account(rid, directory, state):
    record = state.get('replay_account')
    if record is None:
        return
    ctl.require(isinstance(record, dict) and record.get('status') == 'CREATE_ATTEMPTED' and
                isinstance(record.get('name'), str) and re.fullmatch(r'm04_[0-9a-f]{16}', record['name']),
                'invalid replay account record')
    admin_statement(rid, state, "DROP USER IF EXISTS '" + record['name'] + "'@'localhost';")
    state.pop('replay_account')
    ctl.save(directory, state)
