#!/usr/bin/env python3
"""Single-process Unix socket probe, constrained by its transient systemd unit."""
import errno
import json
import os
import signal
import socket
import sys


def probe():
    fds = []
    error = None
    try:
        for _ in range(48):
            try: fds.append(os.open(os.devnull, os.O_RDONLY))
            except OSError as exc:
                if exc.errno != errno.EMFILE: raise
                error = exc.errno
                break
    finally:
        for fd in fds: os.close(fd)
    fd = os.open(os.devnull, os.O_RDONLY)
    os.close(fd)
    return {'errno': error, 'opened': len(fds), 'health': 'ok'}


def main():
    path = sys.argv[1]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        created = os.lstat(path)
        server.listen(2)
        server.settimeout(1)
        running = True
        def quit_service(*_):
            nonlocal running
            running = False
        signal.signal(signal.SIGTERM, quit_service)
        try:
            while running:
                try: client, _ = server.accept()
                except socket.timeout: continue
                with client:
                    client.settimeout(2)
                    if client.recv(32) == b'probe\n':
                        client.sendall(json.dumps(probe()).encode())
        finally:
            try:
                current = os.lstat(path)
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino): os.unlink(path)
            except FileNotFoundError: pass


if __name__ == '__main__': main()
