"""M03 isolated-instance candidate. Not VM-validated; no production entry point.

All commands operate on a freshly created directory and its Unix socket. The
caller must run this as a dedicated unprivileged OS account on a disposable lab.
"""
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

MYSQLD = '/usr/sbin/mysqld'
MYSQL = '/usr/bin/mysql'
TIMEOUT = '/usr/bin/timeout'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
MAX_CONNECTIONS = 10
HOLDER_COUNT = 10
HOLDER_SECONDS = 90
SERVER_SECONDS = 180
MARKER = 'm03_nonsecret_synthetic_only'


class SafetyError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SafetyError(message)


def status_from_error(returncode, stderr):
    return returncode != 0 and bool(re.search(rb'ERROR 1040 \(08004\)', stderr))


class Drill:
    def __init__(self):
        require(os.name == 'posix' and os.geteuid() != 0, 'dedicated unprivileged Linux user required')
        self.root = Path(tempfile.mkdtemp(prefix='opsdrill-m03-', dir='/var/tmp'))
        os.chmod(self.root, 0o700)
        self.data = self.root / 'data'
        self.data.mkdir(mode=0o700)
        self.socket = self.root / 'mysql.sock'
        self.option = self.root / 'test-client.cnf'
        self.server = None
        self.holders = []
        self.uuid = None
        self.phase = 'NEW'

    def command(self, user, statement, timeout=5):
        require(user in ('root', 'm03'), 'unexpected account')
        option = '--no-defaults' if user == 'root' else '--defaults-extra-file=' + str(self.option)
        args = [MYSQL, option, '--protocol=SOCKET', '--socket=' + str(self.socket), '--user=' + user,
                '--connect-timeout=3', '--batch', '--skip-column-names']
        return subprocess.run(args, input=statement.encode('ascii'), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, env=ENV)

    def admin(self, statement):
        result = self.command('root', statement)
        require(result.returncode == 0, 'isolated admin query failed')
        return result.stdout.decode('ascii').strip()

    def verify(self):
        require(self.server is not None and self.server.poll() is None, 'isolated server not running')
        fields = self.admin('SELECT @@datadir,@@socket,@@skip_networking,@@max_connections,@@server_uuid').split('\t')
        require(len(fields) == 5 and Path(fields[0]).resolve() == self.data.resolve()
                and fields[1] == str(self.socket) and fields[2] == '1'
                and fields[3] == str(MAX_CONNECTIONS)
                and re.fullmatch(r'[0-9a-fA-F-]{36}', fields[4]) is not None,
                'isolated instance identity mismatch')
        require(self.uuid is None or fields[4] == self.uuid, 'isolated instance UUID changed')
        return fields[4]

    def start(self):
        require(self.phase == 'NEW', 'invalid start phase')
        base = [MYSQLD, '--no-defaults', '--basedir=/usr', '--datadir=' + str(self.data)]
        init = subprocess.run(base + ['--initialize-insecure'], env=ENV, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=60)
        require(init.returncode == 0, 'isolated initialization failed')
        # timeout supervises the server even if this controller exits abruptly.
        args = [TIMEOUT, '--signal=TERM', '--kill-after=10s', str(SERVER_SECONDS)] + base + [
            '--socket=' + str(self.socket), '--pid-file=' + str(self.root / 'mysql.pid'),
            '--tmpdir=' + str(self.root), '--log-error=' + str(self.root / 'server.log'),
            '--skip-networking', '--skip-log-bin', '--max-connections=' + str(MAX_CONNECTIONS),
            '--innodb-buffer-pool-size=64M', '--performance-schema=OFF']
        self.server = subprocess.Popen(args, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                self.uuid = self.verify()
                break
            except (SafetyError, OSError, subprocess.TimeoutExpired):
                time.sleep(.2)
        require(self.uuid is not None, 'isolated server failed identity checks')
        # This password is a public synthetic marker, not a production credential.
        fd = os.open(self.option, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='ascii') as out:
            out.write('[client]\npassword=' + MARKER + '\n')
        self.verify()
        self.admin("CREATE USER 'm03'@'localhost' IDENTIFIED BY '" + MARKER + "'")
        self.phase = 'READY'

    def inject(self):
        require(self.phase == 'READY', 'invalid inject phase')
        self.verify()
        self.phase = 'INJECTING'
        for _ in range(HOLDER_COUNT):
            args = [TIMEOUT, '--signal=TERM', '--kill-after=5s', str(HOLDER_SECONDS), MYSQL,
                    '--defaults-extra-file=' + str(self.option), '--protocol=SOCKET',
                    '--socket=' + str(self.socket), '--user=m03', '--connect-timeout=3', '--batch']
            self.holders.append(subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                                 stderr=subprocess.DEVNULL, env=ENV, start_new_session=True))
        self.phase = 'INJECTED'

    def check(self):
        require(self.phase in ('INJECTED', 'RELEASED'), 'invalid check phase')
        self.verify()
        connected = self.admin("SHOW GLOBAL STATUS LIKE 'Threads_connected'").split('\t')
        running = self.admin("SHOW GLOBAL STATUS LIKE 'Threads_running'").split('\t')
        sleepers = self.admin("SELECT COUNT(*) FROM information_schema.PROCESSLIST "
                              "WHERE USER='m03' AND COMMAND='Sleep'")
        require(len(connected) == len(running) == 2 and connected[1].isdigit()
                and running[1].isdigit() and sleepers.isdigit(), 'invalid status response')
        probe = self.command('m03', 'SELECT 1')
        limited = status_from_error(probe.returncode, probe.stderr)
        ready = probe.returncode == 0 and probe.stdout.strip() == b'1'
        database_ok = ((self.phase == 'INJECTED' and int(sleepers) == HOLDER_COUNT and limited)
                       or (self.phase == 'RELEASED' and int(sleepers) == 0
                           and int(connected[1]) <= 2 and ready))
        return {'phase': self.phase, 'max_connections': MAX_CONNECTIONS,
                'threads_connected': int(connected[1]), 'threads_running': int(running[1]),
                'synthetic_sleep_connections': int(sleepers), 'too_many_connections': limited,
                'database_readiness': ready, 'database_check': 'PASS' if database_ok else 'FAIL',
                'api_readiness': 'NOT_TESTED',
                'pool_configuration_and_exception_paths': 'NOT_TESTED', 'overall': 'INCOMPLETE'}

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        if process.stdin is not None:
            process.stdin.close()

    def release(self):
        require(self.phase in ('INJECTING', 'INJECTED', 'RELEASED'), 'invalid release phase')
        errors = []
        for process in self.holders:
            try:
                self.stop_process(process)
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(type(exc).__name__)
        require(not errors, 'some connection holders could not be stopped')
        self.phase = 'RELEASED'

    def reset(self):
        errors = []
        for process in self.holders + ([self.server] if self.server is not None else []):
            try:
                self.stop_process(process)
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(type(exc).__name__)
        self.phase = 'RESET_FAILED' if errors else 'STOPPED'
        require(not errors, 'some isolated processes could not be stopped')


def main():
    raise SafetyError('candidate disabled: independent review and real lab validation required')


if __name__ == '__main__':
    main()
