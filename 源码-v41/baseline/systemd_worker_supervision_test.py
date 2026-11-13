"""Bounded experiment: verify systemd stops a worker's owned child on main death."""
import json,os,re,secrets,stat,subprocess,sys,time
from pathlib import Path

def run(args,timeout=15):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
 if p.returncode:raise RuntimeError('command failed: '+Path(args[0]).name)
 return p.stdout.strip()
def props(unit):
 data=run(['/usr/bin/systemctl','show',unit,'-p','LoadState','-p','ActiveState',
           '-p','MainPID','-p','InvocationID','-p','ControlGroup','-p','KillMode','-p','RuntimeMaxUSec'])
 return dict(x.split('=',1) for x in data.splitlines() if '=' in x)
def alive(pid,start):
 try:
  text=(Path('/proc')/str(pid)/'stat').read_text();fields=text[text.rfind(')')+2:].split()
  return len(fields)>19 and fields[19]==start and fields[0]!='Z'
 except FileNotFoundError:return False
def start_time(pid):
 text=(Path('/proc')/str(pid)/'stat').read_text();fields=text[text.rfind(')')+2:].split()
 if len(fields)<=19 or not fields[19].isdigit():raise RuntimeError('process identity unavailable')
 return fields[19]
def save(path,obj):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w',encoding='utf8') as f:
  json.dump(obj,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())

if os.geteuid()!=0 or run(['/usr/bin/systemd-detect-virt','--vm'])!='vmware':raise RuntimeError('VMware lab required')
marker=Path('/etc/opsdrill-lab');s=marker.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or marker.read_bytes().strip()!=b'ops-drill-kit':
 raise RuntimeError('lab marker invalid')
base=Path('/var/backups/opsdrill/Baseline')
for part in (base,*base.parents):
 s=part.lstat()
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('unsafe evidence directory')
rid=secrets.token_hex(8);directory=base/('supervisor-'+rid);directory.mkdir(mode=0o700)
unit='opsdrill-baseline-supervisor-'+rid+'.service';before=props(unit)
if before.get('LoadState')!='not-found':raise RuntimeError('unit collision')
pidfile=directory/'child.json'
worker='''import json,os,subprocess,sys,time
c=subprocess.Popen(['/usr/bin/python3','-I','-B','-c','import time; time.sleep(55)'])
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:json.dump({'child_pid':c.pid},f);f.flush();os.fsync(f.fileno())
time.sleep(55)
'''
save(directory/'intent.json',{'run_id':rid,'unit':unit,'actor':'agent','status':'STARTING'})
print('SUPERVISION_RUN',rid,flush=True)
run(['/usr/bin/systemd-run','--unit='+unit,'--service-type=exec','--property=KillMode=control-group',
     '--property=RuntimeMaxSec=60s','--property=TimeoutStopSec=5s',
     '/usr/bin/python3','-I','-B','-c',worker,str(pidfile)])
deadline=time.monotonic()+10
while not pidfile.exists() and time.monotonic()<deadline:time.sleep(.1)
if not pidfile.exists():raise RuntimeError('worker child receipt unavailable; preserve unit')
info=props(unit);main=int(info.get('MainPID','0'));child=json.loads(pidfile.read_text())['child_pid']
group=info.get('ControlGroup','');invocation=info.get('InvocationID','')
if (info.get('LoadState')!='loaded' or info.get('ActiveState')!='active' or info.get('KillMode')!='control-group'
    or not re.fullmatch('[0-9a-f]{32}',invocation) or invocation=='0'*32
    or group!='/system.slice/'+unit or not main>1 or not isinstance(child,int) or child<=1 or child in (main,os.getpid())
    or info.get('RuntimeMaxUSec') in ('','infinity',None)):
 raise RuntimeError('worker identity mismatch; preserve unit')
members=Path('/sys/fs/cgroup'+group+'/cgroup.procs').read_text().split()
if str(main) not in members or str(child) not in members:raise RuntimeError('child cgroup mismatch; preserve unit')
main_start=start_time(main);child_start=start_time(child)
cmd=(Path('/proc')/str(child)/'cmdline').read_bytes().split(b'\0')
if cmd!=[b'/usr/bin/python3',b'-I',b'-B',b'-c',b'import time; time.sleep(55)',b'']:
 raise RuntimeError('child process mismatch; preserve unit')
save(directory/'bound.json',{'run_id':rid,'unit':unit,'invocation_id':invocation,'control_group':group,
                             'main_pid':main,'main_start_ticks':main_start,'child_pid':child,'child_start_ticks':child_start})
run(['/usr/bin/systemctl','kill','--kill-whom=main','--signal=SIGKILL',unit])
deadline=time.monotonic()+12
while time.monotonic()<deadline:
 if not alive(main,main_start) and not alive(child,child_start):break
 time.sleep(.1)
if alive(main,main_start) or alive(child,child_start):raise RuntimeError('owned processes remain; preserve unit')
cgroup=Path('/sys/fs/cgroup'+group+'/cgroup.procs')
if cgroup.exists() and cgroup.read_text().strip():raise RuntimeError('cgroup still populated; preserve unit')
after=props(unit)
if after.get('ActiveState') not in ('failed','inactive'):raise RuntimeError('unit state not stopped')
save(directory/'result.json',{'run_id':rid,'actor':'agent','status':'PASS','unit_state':after.get('ActiveState'),
                              'main_and_child_stopped':True,'cgroup_empty_or_absent':True,
                              'scope':'synthetic systemd worker; not an import or database recovery'})
print('PASS owned main and child stopped; cgroup empty or absent; unit preserved',unit,flush=True)
