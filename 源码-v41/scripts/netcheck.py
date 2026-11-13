#!/usr/bin/env python3
"""Read-only checks for the OrderGuard local service and lab namespaces."""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

NAMESPACES = ('od-client', 'od-router', 'od-server')


def command(argv, timeout=4):
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False)
        return {'status':'OK' if p.returncode == 0 else 'ERROR', 'exit_code':p.returncode,
                'stdout':p.stdout[:8192].decode('utf-8','replace'),
                'stderr':p.stderr[:2048].decode('utf-8','replace')}
    except FileNotFoundError:
        return {'status':'UNKNOWN', 'exit_code':None, 'reason':'command unavailable'}
    except subprocess.TimeoutExpired:
        return {'status':'UNKNOWN', 'exit_code':None, 'reason':'timeout'}
    except OSError as exc:
        return {'status':'UNKNOWN', 'exit_code':None, 'reason':type(exc).__name__}


def local_http(path):
    start = time.monotonic()
    req = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with req.open('http://127.0.0.1:8080/'+path, timeout=3) as response:
            return {'status':'OK' if response.status == 200 else 'ERROR',
                    'http_code':response.status, 'elapsed_ms':round((time.monotonic()-start)*1000)}
    except urllib.error.HTTPError as exc:
        return {'status':'ERROR', 'http_code':exc.code, 'elapsed_ms':round((time.monotonic()-start)*1000)}
    except (OSError, urllib.error.URLError):
        return {'status':'ERROR', 'http_code':None, 'elapsed_ms':round((time.monotonic()-start)*1000)}


def build_namespace_checks(listing, runner=command):
    found = {line.split()[0] for line in listing.splitlines() if line.split()}
    checks = {}
    for ns in NAMESPACES:
        if ns not in found:
            checks[ns] = {'status':'UNKNOWN', 'reason':'namespace absent'}
            continue
        checks[ns] = {'status':'PRESENT',
                      'addresses':runner(['ip','-n',ns,'-br','address']),
                      'routes':runner(['ip','-n',ns,'route','show'])}
        if ns == 'od-client':
            checks[ns]['dns'] = runner(['ip','netns','exec',ns,'getent','hosts','app.lab'])
            checks[ns]['http'] = runner(['ip','netns','exec',ns,'curl','--noproxy','*',
                                         '--max-time','3','--fail','-sS','-o','/dev/null',
                                         '-w','%{http_code}','http://10.203.2.2:8080/'])
    return checks


def main():
    listing = command(['ip','netns','list'])
    namespaces = (build_namespace_checks(listing['stdout']) if listing['status']=='OK'
                  else {ns:{'status':'UNKNOWN','reason':'namespace listing unavailable'} for ns in NAMESPACES})
    result = {'local_health':local_http('health'), 'local_ready':local_http('ready'),
              'namespaces':namespaces}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__=='__main__':
    sys.exit(main())
