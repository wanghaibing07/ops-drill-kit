#!/usr/bin/env python3
"""Audit a root-protected bounded C01 observation without exposing raw logs."""
import argparse,hashlib,json,os,re,stat,sys
from pathlib import Path

BASE=Path('/var/backups/opsdrill/C01')
ERROR_MARKERS=('pooltimeout','poolclosed','connection pool','database unavailable','traceback','suppressed ','dropped ')
class Refused(ValueError):pass
def need(value,message):
    if not value:raise Refused(message)
def unique(pairs):
    obj={}
    for key,value in pairs:
        if key in obj:raise Refused('duplicate JSON key')
        obj[key]=value
    return obj
def safe_dir(path):
    for p in (path,*path.parents):
        s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'unsafe directory')
def safe_read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=limit,'unsafe evidence file')
        data=f.read(limit+1)
    need(len(data)<=limit,'evidence too large');return data
def decode(raw):return json.loads(raw,object_pairs_hook=unique)
def audit_rows(raw,phase,expected_count,expected_digest):
    need(hashlib.sha256(raw).hexdigest()==expected_digest and raw.endswith(b'\n'),'timing evidence hash')
    rows=[decode(line) for line in raw.splitlines()];need(len(rows)==expected_count and len(rows)>=10,'timing count')
    codes={'baseline':200,'fault':502,'recovered':200};ids=set()
    for row in rows:
        need(isinstance(row,dict) and re.fullmatch(r'[0-9a-f]{32}',str(row.get('request_id',''))) is not None,'invalid timing ID')
        need(row['request_id'] not in ids and str(row.get('status'))==str(codes[phase]),'timing status or duplicate')
        ids.add(row['request_id'])
    return len(rows)
def audit_pools(first,last,start,end):
    need(isinstance(first,dict) and isinstance(last,dict) and first.get('service')==last.get('service'),'service changed')
    one,two=first.get('body'),last.get('body');need(isinstance(one,dict) and isinstance(two,dict),'pool metrics missing')
    need(one.get('scope')==two.get('scope')=='single-process-lab' and one.get('pid')==two.get('pid') and type(one.get('pid')) is int and one['pid']>1,'process mismatch')
    service=first['service'];need(service.get('ActiveState')=='active' and service.get('MainPID')==str(one['pid']) and re.fullmatch(r'[0-9a-f]{32}',str(service.get('InvocationID',''))) is not None,'service identity')
    keys={'closed','timeout','factory','ping','rollback','close','borrower'}
    for name in ('legacy','stage3'):
        a,b=one.get(name),two.get(name);need(isinstance(a,dict) and isinstance(b,dict),'pool absent')
        need(a.get('generation')==b.get('generation') and re.fullmatch(r'[0-9a-f]{32}',str(a.get('generation',''))) is not None,'pool generation changed')
        need(a.get('closed') is False and b.get('closed') is False and a.get('capacity')==b.get('capacity')==4 and a.get('quarantined')==b.get('quarantined')==0,'pool health')
        need(isinstance(a.get('errors'),dict) and set(a['errors'])==keys and a['errors']==b.get('errors') and all(type(v) is int and v>=0 for v in a['errors'].values()),'pool errors')
        need(type(a.get('monotonic_ns')) is int and type(b.get('monotonic_ns')) is int and a['monotonic_ns']<start<end<b['monotonic_ns'],'pool window')
    return service['InvocationID']
def audit_journal(raw,phase,boot,invocation):
    need(hashlib.sha256(raw).hexdigest()==phase.get('journal_sha256') and raw.endswith(b'\n'),'journal evidence hash')
    rows=[decode(line) for line in raw.splitlines()];need(len(rows)==phase.get('journal_entries') and len(rows)>=10,'journal count')
    for row in rows:
        need(row.get('_BOOT_ID')==boot.replace('-','') and row.get('_SYSTEMD_INVOCATION_ID')==invocation,'journal identity')
        ns=int(row['__MONOTONIC_TIMESTAMP'])*1000;need(phase['monotonic_start_ns']<=ns<=phase['monotonic_end_ns'],'journal window')
        message=str(row.get('MESSAGE','')).lower();need(not any(x in message for x in ERROR_MARKERS),'journal error marker')
    return len(rows)
def audit_lifecycle(events,result):
    """Tie the measured windows to this run's actual event chronology."""
    need(events and all(type(e.get('monotonic_ns')) is int and e['monotonic_ns']>0 for e in events),'event timestamp')
    times=[e['monotonic_ns'] for e in events]
    need(all(a<b for a,b in zip(times,times[1:])),'event order')
    def one(kind,outcome):
        matches=[e['monotonic_ns'] for e in events if e.get('event')==kind and e.get('result')==outcome]
        need(len(matches)==1,'missing or duplicate lifecycle event')
        return matches[0]
    starting=one('inject','STARTING'); injected=one('inject','PASS')
    pending=one('check','PENDING'); diagnosis=one('diagnosis','PASS')
    resolved=one('resolve','MITIGATED'); partial=one('check','PARTIAL'); reset=one('reset','PASS')
    b,f,r=(result[n] for n in ('baseline','fault','recovered'))
    need(b['monotonic_end_ns']<starting<injected<pending<f['monotonic_start_ns']<f['monotonic_end_ns']<diagnosis<resolved<partial<r['monotonic_start_ns']<r['monotonic_end_ns']<reset,'window/event binding')
def audit(directory,rid,expected_sha):
    need(os.geteuid()==0,'root required')
    need(re.fullmatch(r'[0-9a-f]{24}',rid) is not None and re.fullmatch(r'[0-9a-f]{64}',expected_sha) is not None,'invalid identity or hash')
    need(directory.parent==BASE and re.fullmatch(r'window-metrics-[0-9a-f]{16}',directory.name) is not None,'unexpected evidence path');safe_dir(directory)
    raw=safe_read(directory/'result.json',1048576);need(hashlib.sha256(raw).hexdigest()==expected_sha,'result hash mismatch');result=decode(raw)
    need(result.get('actor')=='agent' and result.get('run_id')==rid and result.get('status')=='BOUNDED_AUTOMATED_OBSERVATION_PASS' and result.get('ready_after')==200 and result.get('cli_check')=='RECOVERED_PARTIAL','result identity')
    safe_dir(Path('/var/lib/opsdrill'));eventraw=safe_read(Path('/var/lib/opsdrill/events.jsonl'),16777216);events=[decode(line) for line in eventraw.splitlines()]
    owned=[e for e in events if e.get('drill_id')=='C01' and e.get('run_id')==rid]
    need(owned and all(e.get('actor')=='agent' for e in owned) and len({e.get('attempt_id') for e in owned})==1 and len({e.get('boot_id') for e in owned})==1,'event identity')
    need(any(e.get('event')=='inject' and e.get('result')=='PASS' for e in owned) and any(e.get('event')=='check' and e.get('result')=='PARTIAL' for e in owned) and any(e.get('event')=='reset' and e.get('result')=='PASS' for e in owned),'event lifecycle')
    boot=owned[0]['boot_id'];need(re.fullmatch(r'[0-9a-f-]{36}',str(boot)) is not None,'boot identity')
    previous=None;previous_offset=None;device=None;counts={}
    for name in ('baseline','fault','recovered'):
        p=result.get(name);need(isinstance(p,dict) and p.get('phase')==name,'phase missing')
        start,end=p.get('monotonic_start_ns'),p.get('monotonic_end_ns');need(type(start) is int and type(end) is int and 0<start<end and (previous is None or previous<start),'phase timing');previous=end
        a,b=p.get('start_offset'),p.get('end_offset');need(type(a) is int and type(b) is int and 0<=a<b and b-a<=1048576 and (previous_offset is None or previous_offset<=a),'log offsets');previous_offset=b
        identity=p.get('log_identity');need(isinstance(identity,list) and len(identity)==2 and all(type(x) is int and x>0 for x in identity),'log identity')
        if device is None:device=identity
        need(device==identity,'log rotated')
        data=safe_read(directory/(name+'-timing.jsonl'),1048576);need(len(data)==b-a,'log length mismatch')
        count=audit_rows(data,name,p.get('requests'),p.get('timing_sha256'));need(p.get('own_requests')==10,'own requests missing')
        expected={'baseline':{'200':count},'fault':{'502':count},'recovered':{'200':count}}[name];need(p.get('status_counts')==expected,'status counts mismatch')
        counts[name]=count
        if name=='recovered':
            invocation=audit_pools(p.get('pool_before'),p.get('pool_after'),start,end)
            journal=safe_read(directory/'recovered-journal.jsonl',4000000);audit_journal(journal,p,boot,invocation)
    audit_lifecycle(owned,result)
    return {'run_id':rid,'attempt_id':owned[0]['attempt_id'],'actor':'agent','status':'BOUNDED_OBSERVATION_PASS','scope':'finite target gateway windows and two recovery-window pools; not complete C01 or global zero errors','requests':counts,'result_sha256':expected_sha}
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-id',required=True);parser.add_argument('--evidence-dir',required=True);parser.add_argument('--expected-sha256',required=True);args=parser.parse_args()
    try:print(json.dumps(audit(Path(args.evidence_dir),args.run_id,args.expected_sha256),sort_keys=True));return 0
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc:
        print('C01 audit refused: '+(str(exc) if isinstance(exc,Refused) else type(exc).__name__),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
