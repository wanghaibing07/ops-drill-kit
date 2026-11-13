"""Read-only Linux L02 preflight. No injection/reset implementation.

Run as root inside the lab only after review. It executes fixed read-only
commands with a sanitized environment and does not persist observations.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from l02_policy import Refused, parse_ports, port_type, require

ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LANG':'C', 'LC_ALL':'C'}

def cmd(*args):
    p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True, env=ENV, timeout=15, check=False)
    require(p.returncode == 0, 'read-only command failed: ' + Path(args[0]).name)
    return p.stdout


def secure_marker():
    fd = os.open('/etc/opsdrill-lab', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= 64, 'unsafe marker')
        require(os.read(fd,65).strip() == b'ops-drill-kit', 'invalid marker')
    finally: os.close(fd)


def listening_tcp(port, contents):
    """Both proc tables must be read by caller. Any bound TCP port is occupied."""
    for table in contents:
        lines = table.splitlines()
        require(bool(lines) and 'local_address' in lines[0], 'invalid proc tcp table')
        for line in lines[1:]:
            fields = line.split()
            require(len(fields) >= 4 and re.fullmatch(r'[0-9A-Fa-f]+:[0-9A-Fa-f]{4}', fields[1])
                    and re.fullmatch(r'[0-9A-Fa-f]{2}', fields[3]), 'invalid proc tcp row')
            # Any TCP socket, including non-LISTEN and TIME_WAIT, fails closed.
            if int(fields[1].split(':')[1],16) == port:
                return True
    return False


def inspect(port):
    require(type(port) is int and 1024 <= port <= 65535, 'invalid port')
    require(os.geteuid() == 0, 'root required')
    require(cmd('/usr/bin/systemd-detect-virt','--vm').strip() == 'vmware', 'not VMware')
    secure_marker()
    require(cmd('/usr/sbin/getenforce').strip() == 'Enforcing', 'SELinux not Enforcing')
    effective = parse_ports(cmd('/usr/sbin/semanage','port','-l'))
    local = parse_ports(cmd('/usr/sbin/semanage','port','-l','-C'))
    occupied = listening_tcp(port, [Path('/proc/net/tcp').read_text(encoding='ascii'),
                                    Path('/proc/net/tcp6').read_text(encoding='ascii')])
    return {'port':port, 'effective_listed_type':port_type(effective,port),
            'local_listed_type':port_type(local,port), 'tcp_socket_present':occupied,
            'guard_passed':True, 'enforcing':True,
            'decision':'REFUSE_INJECTION_UNIMPLEMENTED',
            'limitations':['unlisted does not prove effective bind denial',
                           'observations are not atomic with a subsequent mutation',
                           'no service, audit, mapping ownership or watchdog validation']}


def main():
    require(len(sys.argv) == 2 and re.fullmatch(r'[0-9]{1,5}',sys.argv[1]) is not None, 'usage: l02_linux_inspect.py PORT')
    print(json.dumps(inspect(int(sys.argv[1])),sort_keys=True))

if __name__ == '__main__':
    try: main()
    except (Refused, OSError, subprocess.SubprocessError, ValueError) as exc:
        print('l02: ' + str(exc), file=sys.stderr)
        sys.exit(2)
