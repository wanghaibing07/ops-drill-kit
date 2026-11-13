#!/usr/bin/env python3
"""Summarize recorded drill events without inventing actors or times."""
import argparse
import collections
import json
import re
import sys

DRILL = re.compile(r'^(?:L0[1-4]|N0[1-4]|M0[1-4]|C01)$')
ATTEMPT = re.compile(r'^(?:L0[1-4]|N0[1-4]|M0[1-4]|C01)-[0-9]{8}-[0-9]{3,6}$')
MAX_LINE = 65536


def duration(start, end):
    if not start or not end or start.get('actor') not in ('user','agent') or start.get('actor') != end.get('actor'):
        return None
    if not start.get('boot_id') or start.get('boot_id') != end.get('boot_id'):
        return None
    a, b = start.get('monotonic_ns'), end.get('monotonic_ns')
    if type(a) is not int or type(b) is not int or b < a:
        return None
    return round((b-a)/1_000_000_000, 3)


def validate_bounded_io(before, after, *, run_id, elapsed_ns, application_read_bytes,
             storage_read_bytes, health_before, health_after):
    """Return PASS only for complete same-device, same-cgroup bounded evidence.

    Hardware condition and attribution of host-wide iowait are outside scope.
    """
    import re
    if not isinstance(run_id,str) or not re.fullmatch(r'[0-9a-f]{24}',run_id):return False
    if not isinstance(before,dict) or not isinstance(after,dict):return False
    keys={'device','limit_device','unit','limit_bps','disk_read_sectors','cgroup_read_bytes','monotonic_ns'}
    if set(before)!=keys or set(after)!=keys:return False
    if before['device']!=after['device'] or before['limit_device']!=after['limit_device']:return False
    if before['unit']!=after['unit'] or before['unit']!='opsdrill-l03-'+run_id+'.service':return False
    if before['limit_bps']!=32000000 or after['limit_bps']!=32000000:return False
    for sample in (before,after):
        if not isinstance(sample['device'],str) or not re.fullmatch(r'[0-9]+:[0-9]+',sample['device']):return False
        if not isinstance(sample['limit_device'],str) or not re.fullmatch(r'[0-9]+:[0-9]+',sample['limit_device']):return False
        if any(type(sample[k]) is not int or sample[k]<0 for k in ('disk_read_sectors','cgroup_read_bytes','monotonic_ns','limit_bps')):return False
    if type(elapsed_ns) is not int or not 0<elapsed_ns<=30000000000:return False
    if type(application_read_bytes) is not int or application_read_bytes!=268435456:return False
    if type(storage_read_bytes) is not int or storage_read_bytes<67108864:return False
    if health_before is not True or health_after is not True:return False
    if not 0<after['monotonic_ns']-before['monotonic_ns']<=30000000000:return False
    if after['disk_read_sectors']<=before['disk_read_sectors']:return False
    if after['cgroup_read_bytes']<=before['cgroup_read_bytes']:return False
    return True


def l03_details_valid(details):
    if not isinstance(details,dict) or set(details)!={'run_id','l03_contract','io_evidence','elapsed_ns','read_bytes','storage_read_bytes','health_before','health_after'}: return False
    if details['l03_contract']!='bounded-io-v1': return False
    evidence=details['io_evidence']
    if not isinstance(evidence,dict) or set(evidence)!={'before','after'}: return False
    return validate_bounded_io(evidence['before'],evidence['after'],run_id=details['run_id'],
        elapsed_ns=details['elapsed_ns'],application_read_bytes=details['read_bytes'],
        storage_read_bytes=details['storage_read_bytes'],health_before=details['health_before'],health_after=details['health_after'])


def summarize(lines):
    attempts = collections.OrderedDict()
    invalid = 0
    for line in lines:
        if len(line) > MAX_LINE:
            invalid += 1
            continue
        try:
            event = json.loads(line)
            if not isinstance(event, dict): raise ValueError()
            drill, attempt, kind = event.get('drill_id'), event.get('attempt_id'), event.get('event')
            if not isinstance(drill,str) or not DRILL.fullmatch(drill): raise ValueError()
            if not isinstance(attempt,str) or not ATTEMPT.fullmatch(attempt): raise ValueError()
            if not attempt.startswith(drill+'-'): raise ValueError()
            if drill=='C01' and (not isinstance(event.get('run_id'),str) or not re.fullmatch(r'[0-9a-f]{24}',event['run_id'])): raise ValueError()
            if drill=='M04' and 'run_id' in event and (not isinstance(event['run_id'],str) or not re.fullmatch(r'[0-9a-f]{16}',event['run_id'])): raise ValueError()
            if kind not in ('inject','diagnosis','check','hint','reset') and not (drill in ('C01','M04') and kind=='resolve'): raise ValueError()
        except (ValueError,TypeError,json.JSONDecodeError):
            invalid += 1
            continue
        attempts.setdefault((drill,attempt), []).append(event)
    rows = []
    for (drill, attempt), events in attempts.items():
        start_index = next((i for i,x in enumerate(events) if x['event']=='inject' and x.get('result')=='PASS'),None)
        start = events[start_index] if start_index is not None else None
        subsequent = events[start_index+1:] if start_index is not None else []
        diagnosis = next((x for x in subsequent if x['event']=='diagnosis'),None)
        # C01 and L03 lack independent evidence for full recovery.
        passed = None if drill in ('C01','L03') else next((x for x in subsequent if x['event']=='check' and x.get('result')=='PASS'),None)
        allowed_checks = ('PARTIAL','FAIL','PENDING') if drill in ('C01','L03') else ('PASS','FAIL')
        checks = [x for x in subsequent if x['event']=='check' and x.get('result') in allowed_checks]
        if drill=='L03':
            checks = [x for x in subsequent if x['event']=='check' and (x.get('result') in allowed_checks or (x.get('result')=='PASS' and l03_details_valid({k:x.get(k) for k in ('run_id','l03_contract','io_evidence','elapsed_ns','read_bytes','storage_read_bytes','health_before','health_after')})))]
        injections = [x for x in events if x['event']=='inject' and x.get('result')=='PASS']
        nonzero_checks = sum(x['event']=='check' and x.get('result') in (('FAIL','PENDING','PARTIAL') if drill in ('C01','L03') else ('FAIL','PENDING')) for x in events)
        # Failed or interrupted injection has no PASS start, but its actor can
        # still be reported when every injection event agrees on a known actor.
        if start:
            actor = start.get('actor')
        else:
            actors = [x.get('actor') for x in events if x['event']=='inject']
            actor = actors[0] if actors and all(x==actors[0] for x in actors) else None
        actor = actor if actor in ('user','agent') else 'unknown'
        ids = [x.get('run_id') for x in events] if drill in ('C01','M04') else []
        runs = {x for x in ids if x is not None}
        identity_invalid = (drill=='C01' and len(runs)!=1) or (drill=='M04' and bool(runs) and (len(runs)!=1 or any(x is None for x in ids)))
        scoped = drill=='L03' and bool(checks) and checks[-1].get('result')=='PASS'
        last_check = next((i for i in range(len(subsequent)-1,-1,-1) if scoped and subsequent[i] is checks[-1]),None)
        resets = [x for x in subsequent[last_check+1:] if x['event']=='reset'] if scoped else []
        cleaned = len(resets)>=2 and resets[-2].get('result')=='PASS' and resets[-1].get('result')=='CLEAN'
        rows.append({'drill_id':drill,'attempt_id':attempt,
                     **({'run_id':next(iter(runs)) if len(runs)==1 and not identity_invalid else None} if drill in ('C01','M04') else {}),
                     **({'scope':'bounded_io_simulation'} if scoped else {}),
                     'actor':actor,
                     'status':('INVALID' if len(injections)>1 or identity_invalid else 'PARTIAL' if scoped and not cleaned else checks[-1]['result'] if checks else 'INCOMPLETE'),
                     'nonzero_checks':nonzero_checks,
                     'hint_count':sum(x['event']=='hint' for x in events),
                     'mttd_proxy_seconds':duration(start,diagnosis) if len(injections)==1 and not identity_invalid else None,
                     'mttr_proxy_seconds':duration(start,passed) if len(injections)==1 and not identity_invalid else None})
    return {'attempts':rows, 'invalid_lines':invalid,
            'note':'Times require the same recorded actor and a shared boot monotonic clock; agent times are automation, not manual timings.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('events',nargs='?',default='/var/lib/opsdrill/events.jsonl')
    p.add_argument('--markdown',action='store_true',help='render a Markdown summary on stdout')
    args=p.parse_args()
    try:
        with open(args.events,encoding='utf-8') as f: result=summarize(f)
    except FileNotFoundError:
        result=summarize([])
        result['source_status']='NOT_FOUND'
    except (OSError, UnicodeError) as exc:
        print('event read failed: '+type(exc).__name__,file=sys.stderr)
        return 2
    if args.markdown:
        print('# 演练结果\n')
        if not result['attempts']:
            print('未找到可用演练记录；不能据此判断是否曾经练习。')
        else:
            print('| 演练 | 记录 | 执行者 | 状态 | 非零检查（含进行中） | 提示 | MTTD proxy 秒 | MTTR proxy 秒 |')
            print('| --- | --- | --- | --- | ---: | ---: | ---: | ---: |')
            for row in result['attempts']:
                actor = row['actor'] if row['actor'] in ('user','agent','unknown') else 'unknown'
                a = row['mttd_proxy_seconds'] if row['mttd_proxy_seconds'] is not None else '未知'
                b = row['mttr_proxy_seconds'] if row['mttr_proxy_seconds'] is not None else '未知'
                print('| {drill_id} | {attempt_id} | {actor} | {status} | {nonzero_checks} | {hint_count} | {a} | {b} |'.format(**{**row,'attempt_id':row['attempt_id']+(' (run '+(row.get('run_id') or '未知')+')' if row['drill_id'] in ('C01','M04') and row.get('run_id') else ''),'actor':actor,'status':row['status']+(' (受控模拟)' if row.get('scope')=='bounded_io_simulation' else ''),'a':a,'b':b}))
        print('\n无效记录数：%d。时间只对同一启动周期、同一执行者的单调时钟记录计算；agent 表示自动运行耗时。' % result['invalid_lines'])
    else:
        print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0


if __name__=='__main__': sys.exit(main())
