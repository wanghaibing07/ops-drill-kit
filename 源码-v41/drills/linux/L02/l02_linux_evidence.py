"""Linux read-only process, audit and listener identity checks for L02."""
import re
import os
import selectors
import time
import subprocess
from pathlib import Path
from l02_policy import Refused, require
from l02_audit import verify_denial

ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}


def run_checked(argv,limit=4*1024*1024):
    require(type(limit) is int and 0<limit<=4*1024*1024,'invalid capture limit')
    p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV)
    result=bytearray()
    selector=selectors.DefaultSelector()
    try:
        for stream,kind in ((p.stdout,'stdout'),(p.stderr,'stderr')):
            os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,kind)
        deadline=time.monotonic()+20
        while selector.get_map():
            remaining=deadline-time.monotonic()
            require(remaining>0,'read-only evidence command timed out')
            for key,_ in selector.select(remaining):
                try: data=os.read(key.fileobj.fileno(),65536)
                except BlockingIOError: continue
                if not data:
                    selector.unregister(key.fileobj)
                elif key.data=='stdout':
                    require(len(result)+len(data)<=limit,'read-only evidence output oversized')
                    result.extend(data)
        remaining=deadline-time.monotonic()
        require(remaining>0,'read-only evidence command timed out')
        require(p.wait(timeout=remaining)==0,'read-only evidence command failed')
        return bytes(result).decode('utf-8','strict')
    finally:
        selector.close()
        if p.poll() is None:
            p.kill()
            p.wait(timeout=5)
        p.stdout.close(); p.stderr.close()


def proc_start_ticks(stat_line):
    # comm may contain spaces or parentheses. Field 22 is index 19 after comm.
    match=re.fullmatch(r'\d+ \(.*\) (.*)',stat_line.strip())
    require(match is not None,'bad proc stat')
    fields=match.group(1).split()
    require(len(fields)>19 and fields[19].isdigit(),'bad proc start time')
    return int(fields[19])


def proc_identity(pid,run_id,expected_ticks):
    require(type(pid) is int and pid>0 and type(expected_ticks) is int and expected_ticks>0,'bad process identity')
    proc=Path('/proc')/str(pid)
    require(proc_start_ticks((proc/'stat').read_text(encoding='ascii'))==expected_ticks,'PID recycled')
    require((proc/'exe').resolve(strict=True)==Path('/usr/sbin/nginx'),'wrong process executable')
    cgroup=(proc/'cgroup').read_text(encoding='ascii')
    require(any(line.split(':',2)[-1]=='/system.slice/opsdrill-l02-'+run_id+'.service' for line in cgroup.splitlines()),'wrong process cgroup')
    return True


def unit_process(run_id):
    unit='opsdrill-l02-'+run_id+'.service'
    text=run_checked(['/usr/bin/systemctl','show',unit,'--no-pager','--property=InvocationID,ExecMainPID'])
    values={}
    for line in text.splitlines():
        if '=' in line:
            key,value=line.split('=',1); require(key not in values,'duplicate systemd field'); values[key]=value
    require(re.fullmatch(r'[0-9a-f]{32}',values.get('InvocationID','')) is not None,'bad invocation ID')
    require(re.fullmatch(r'[1-9][0-9]*',values.get('ExecMainPID','')) is not None,'missing unit PID')
    return values['InvocationID'],int(values['ExecMainPID'])


def verify_fault(run_id,port,evidence):
    require(isinstance(evidence,dict) and set(evidence)=={'invocation','pid','start_ticks','started_epoch','target_type'},'invalid fault evidence')
    invocation,pid=unit_process(run_id)
    require(invocation==evidence['invocation'] and pid==evidence['pid'],'unit invocation changed')
    proc_identity(pid,run_id,evidence['start_ticks'])
    raw=run_checked(['/usr/sbin/ausearch','--input-logs','--raw','-m','AVC','-ts','boot'])
    import time
    return verify_denial(raw.splitlines(),min_seconds=evidence['started_epoch'],max_seconds=int(time.time()),
                         pid=pid,executable='/usr/sbin/nginx',port=port,expected_target_type=evidence['target_type'])


def listener_pids(ss_text,port):
    require(type(port) is int and 1024<=port<=65535,'bad port')
    matches=[]
    for line in ss_text.splitlines():
        fields=line.split()
        require(len(fields)>=4,'bad ss output')
        if fields[3]=='127.0.0.1:'+str(port):
            ids=re.findall(r'\bpid=(\d+)',line)
            require(ids,'listener has no process identity')
            matches.extend(int(x) for x in ids)
    require(matches,'owned listener missing')
    return sorted(set(matches))


def verify_listener(run_id,port):
    text=run_checked(['/usr/sbin/ss','-H','-lntp'])
    pids=listener_pids(text,port)
    for pid in pids:
        proc=Path('/proc')/str(pid)
        require((proc/'exe').resolve(strict=True)==Path('/usr/sbin/nginx'),'foreign listener')
        group=(proc/'cgroup').read_text(encoding='ascii')
        require(any(line.split(':',2)[-1]=='/system.slice/opsdrill-l02-'+run_id+'.service' for line in group.splitlines()),'listener outside service')
    return True


def capture_live_identity(run_id):
    """Capture an alive, authenticated unit PID; never accepts caller PID."""
    require(re.fullmatch(r'[0-9a-f]{24}',run_id or '') is not None,'invalid run id')
    invocation,pid=unit_process(run_id)
    ticks=proc_start_ticks((Path('/proc')/str(pid)/'stat').read_text(encoding='ascii'))
    proc_identity(pid,run_id,ticks)
    uptime=float(Path('/proc/uptime').read_text(encoding='ascii').split()[0])
    rate=os.sysconf('SC_CLK_TCK')
    require(rate>0 and 0<ticks/rate<=uptime,'invalid process start time')
    epoch=int(time.time()-uptime+ticks/rate)-1
    require(epoch>0,'invalid start epoch')
    return {'invocation':invocation,'pid':pid,'start_ticks':ticks,
            'started_epoch':epoch,'target_type':'port_t'}
