#!/usr/bin/python3
"""Bounded Nginx upstream-keepalive comparison inside a new network namespace."""
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time

if os.geteuid() != 0 or not Path('/etc/opsdrill-lab').is_file():
    raise SystemExit('lab root required')
if Path('/etc/opsdrill-lab').read_text().strip() != 'ops-drill-kit':
    raise SystemExit('invalid lab marker')
if subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,check=False).stdout.strip() != 'vmware':
    raise SystemExit('VMware required')
if os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino:
    raise SystemExit('refusing default network namespace')
subprocess.run(['/usr/sbin/ip','link','set','lo','up'],check=True)
run_id=secrets.token_hex(8)
root=Path('/var/backups/opsdrill/N04')/('nginx-keepalive-'+run_id)
root.mkdir(mode=0o700)
os.chmod(root,0o700)
class Backend(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,*args):
        super().__init__(*args); self.counter=0; self.ids={}; self.lock=threading.Lock()
    def get_request(self):
        conn, addr=super().get_request()
        with self.lock:
            self.counter+=1; self.ids[conn]=self.counter
        return conn,addr
class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):
        value=str(self.server.ids[self.connection]); body=b'ok'
        self.send_response(200);self.send_header('Content-Length',str(len(body)))
        self.send_header('X-Backend-Connection',value);self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass
backend=Backend(('127.0.0.1',18082),Handler)
thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
observations={}
try:
    for label,keepalive in [('without_keepalive',False),('with_keepalive',True)]:
        conf=root/(label+'.conf')
        conf.write_text('worker_processes 1;\nerror_log stderr notice;\npid '+str(root/(label+'.pid'))+';\n'
            'events { worker_connections 128; }\nhttp { access_log off; upstream backend { server 127.0.0.1:18082; '
            +('keepalive 4;' if keepalive else '')+' } server { listen 127.0.0.1:18081; location / { '
            'proxy_http_version 1.1; proxy_set_header Connection ""; proxy_pass http://backend; } } }\n')
        err=(root/(label+'.log')).open('wb')
        proc=subprocess.Popen(['/usr/sbin/nginx','-c',str(conf),'-g','daemon off;'],stdout=subprocess.DEVNULL,stderr=err)
        try:
            deadline=time.monotonic()+5
            while True:
                if proc.poll() is not None: raise RuntimeError('nginx exited before readiness')
                try:
                    client=http.client.HTTPConnection('127.0.0.1',18081,timeout=1)
                    client.connect();client.close();break
                except OSError:
                    if time.monotonic()>=deadline: raise RuntimeError('nginx did not become ready')
                    time.sleep(.05)
            ids=[]
            for _ in range(8):
                client=http.client.HTTPConnection('127.0.0.1',18081,timeout=3)
                try:
                    client.request('GET','/',headers={'Connection':'close'})
                    response=client.getresponse(); body=response.read()
                    if response.status!=200 or body!=b'ok': raise RuntimeError('request failed')
                    ids.append(response.getheader('X-Backend-Connection'))
                finally: client.close()
            if any(not x or not x.isdigit() for x in ids): raise RuntimeError('invalid connection identity')
            observations[label]={'requests':len(ids),'backend_connection_ids':ids,'backend_connections':len(set(ids))}
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill();proc.wait(timeout=3)
            err.close()
    if observations['without_keepalive']['backend_connections'] != 8 or observations['with_keepalive']['backend_connections'] != 1:
        raise RuntimeError('connection reuse comparison did not meet expected observations')
    result={'run_id':run_id,'actor':'agent','namespace':'anonymous unshare --net','observations':observations,
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (root/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True));print('evidence:',root)
finally:
    backend.shutdown();backend.server_close();thread.join(timeout=3)
