import base64
exec(compile(base64.b64decode('IiIiQ29uc2VydmF0aXZlIGNsYXNzaWZpY2F0aW9uIG9mIGFuIGludGVycnVwdGVkIGlzb2xhdGVkIGltcG9ydCBiYXRjaC4KClRoZSBjYWxsZXIgbXVzdCBpbmRlcGVuZGVudGx5IHZlcmlmeSB0aGUgY3VycmVudCBydW4gYW5kIE15U1FMIGluc3RhbmNlIGFuZApkZXJpdmUgYm90aCBleHBlY3RlZCBoYXNoZXMgZnJvbSB0aGUgdmFsaWRhdGVkLCBvcmRlcmVkIHNvdXJjZSBkYXRhLiAgVGhpcwptb2R1bGUgZG9lcyBub3QgY29ubmVjdCB0byBNeVNRTCwgcGVyc2lzdCBzdGF0ZSwgb3IgcGVyZm9ybSBhIHJldHJ5LgoiIiIKaW1wb3J0IHJlCgpfU0hBID0gcmUuY29tcGlsZShyJ1swLTlhLWZdezY0fVxaJykKCgpkZWYgcmVjb25jaWxlKCosIGluc3RhbmNlX3ZlcmlmaWVkLCBzdGFydCwgZW5kLCBhY3R1YWxfY291bnQsIGFjdHVhbF9zaGEsCiAgICAgICAgICAgICAgZXhwZWN0ZWRfYmVmb3JlX3NoYSwgZXhwZWN0ZWRfYWZ0ZXJfc2hhKToKICAgICIiIlJldHVybiBhbiBvYnNlcnZhdGlvbiwgbmV2ZXIgZXhlY3V0ZSBvciBhdXRob3JpemUgYSBkYXRhYmFzZSBjaGFuZ2UuIiIiCiAgICBpZiBpbnN0YW5jZV92ZXJpZmllZCBpcyBub3QgVHJ1ZToKICAgICAgICByZXR1cm4gJ0lERU5USVRZX1VOVkVSSUZJRUQnCiAgICBpZiAodHlwZShzdGFydCkgaXMgbm90IGludCBvciB0eXBlKGVuZCkgaXMgbm90IGludCBvciB0eXBlKGFjdHVhbF9jb3VudCkgaXMgbm90IGludAogICAgICAgICAgICBvciBub3QgMSA8PSBzdGFydCA8PSBlbmQgPD0gNTAwMDAwIG9yIG5vdCAwIDw9IGFjdHVhbF9jb3VudCA8PSA1MDAwMDAKICAgICAgICAgICAgb3IgYW55KG5vdCBpc2luc3RhbmNlKHgsc3RyKSBvciBub3QgX1NIQS5mdWxsbWF0Y2goeCkKICAgICAgICAgICAgICAgICAgIGZvciB4IGluIChhY3R1YWxfc2hhLGV4cGVjdGVkX2JlZm9yZV9zaGEsZXhwZWN0ZWRfYWZ0ZXJfc2hhKSkpOgogICAgICAgIHJldHVybiAnTkVFRFNfSU5TUEVDVElPTicKICAgIGlmIGFjdHVhbF9jb3VudCA9PSBzdGFydC0xIGFuZCBhY3R1YWxfc2hhID09IGV4cGVjdGVkX2JlZm9yZV9zaGE6CiAgICAgICAgcmV0dXJuICdNQVRDSEVTX0JFRk9SRV9CQVRDSCcKICAgIGlmIGFjdHVhbF9jb3VudCA9PSBlbmQgYW5kIGFjdHVhbF9zaGEgPT0gZXhwZWN0ZWRfYWZ0ZXJfc2hhOgogICAgICAgIHJldHVybiAnTUFUQ0hFU19BRlRFUl9CQVRDSCcKICAgIHJldHVybiAnTkVFRFNfSU5TUEVDVElPTicK'),'<journal_classifier>','exec'))
EXPECTED={'orders-500000-reference.tsv': (1, 500000, '283a3a0453f2d1945ad33e81a0425ee4cf51bc59d8553bb2936901641f66993b'), 'orders-50000-reference.tsv': (1, 50000, '9d3b71e677e1b9619069cee1064ca04e61376baf096a3793ab78ce01f31f2e16'), 'orders-1000-whole.tsv': (1, 1000, '14ac915c8ce2abd0e18ef22ea1bf7ee0ecb4b92de4c478e501c3d38aa851e6c8'), 'orders-1001-50000.tsv': (1001, 50000, '8a33eb1e84cd9a960820fddf0c1c871e4e7f01845df6bd34e0cf9985082199bd'), 'orders-50001-100000.tsv': (50001, 100000, '6250d5f820ec542c716c59049d814415edb819237ce3020d1968b4fe8d798018'), 'orders-100001-150000.tsv': (100001, 150000, '74864abbf242561f3949e57d643cafa400493422b4d688de305b62b7c6a2240a'), 'orders-150001-200000.tsv': (150001, 200000, 'f09bdd6a085133192b2544dd3a243f89a0bcbed35366dc2c40293d63fc3ae68c'), 'orders-200001-250000.tsv': (200001, 250000, '4725e7a48ae1b82ea929c0f7712964c15d8c2b9cb2c9c91caf1bdb1e32c50d96'), 'orders-250001-300000.tsv': (250001, 300000, 'ce4c368103906b78961c0abedafab60b9a17aa04f861783381137f86d48d7313'), 'orders-300001-350000.tsv': (300001, 350000, 'd42f276b7a35384bf2d8520d274387a40ca61eab40cbba57deeffadd36f3eb6f'), 'orders-350001-400000.tsv': (350001, 400000, 'd27ae6c529685081cb15ef60866775c04cbfd3e3ea91d30818a7393ab8d288be'), 'orders-400001-450000.tsv': (400001, 450000, 'ebe30c7015053d39295a27af4464827f5ad576aa62b77e50cbcbcae11862a5e0'), 'orders-450001-500000.tsv': (450001, 500000, '0d17cf15dee8f55be059f040da0bbd523202e731f40ad5e3d159cd20168ac31b')}
"""Read-only reconciliation for an active isolated baseline-import run.

This does not resume, change journal, stop services, or delete files. Run only
from a reviewed root-controlled staging directory in the authorized VM.
"""
import fcntl,hashlib,json,os,pwd,re,stat,subprocess,sys
from pathlib import Path

ROOT=Path('/usr/local/libexec/opsdrill/m04-synthetic-v2')
PINNED={
 'm04_controller.py':'46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9',
 'continuation/mysql_live_identity.py':'c294cfa07973ef9342d4ca65147da14acbe6fa155ad29623edcda31fc48a42be',
 'continuation/mysql_reset_gate.py':'eff466c8ad9dc5f7d2012a1b93aca33ffbb763d52ba8c39429f34ad7623178af'}

def checked(path,sha,limit,uid,mode=None):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not (stat.S_ISREG(st.st_mode) and st.st_uid==uid and st.st_nlink==1 and st.st_size<=limit
                and (mode is None or stat.S_IMODE(st.st_mode)==mode)):
            raise RuntimeError('unsafe input')
        with os.fdopen(fd,'rb') as f:fd=-1;data=f.read(limit+1)
    finally:
        if fd>=0:os.close(fd)
    if len(data)>limit or hashlib.sha256(data).hexdigest()!=sha:raise RuntimeError('input digest mismatch')
    return data

def main():
    if os.geteuid()!=0 or len(sys.argv)!=2 or not re.fullmatch(r'[0-9a-f]{16}',sys.argv[1]):
        raise RuntimeError('root and exactly one run ID required')
    for directory in (ROOT,ROOT/'continuation'):
        st=directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077:raise RuntimeError('unsafe controller directory')
    for name,sha in PINNED.items():checked(ROOT/name,sha,1024*1024,0)
    sys.path[:0]=[str(ROOT),str(ROOT/'continuation')]
    import m04_controller as ctl
    import mysql_live_identity as identity
    from mysql_reset_gate import InstanceIdentity
    if not os.path.lexists(ctl.BASE):raise RuntimeError('controller state absent')
    ctl.setup();rid=sys.argv[1];directory=ctl.BASE/rid;ctl.secure_dir(directory)
    fd=os.open(directory/'.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o077:
            raise RuntimeError('unsafe lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state=ctl.load(directory,rid);ctl.require_same_boot(state)
        if (state.get('phase')!='READY' or state.get('business_phase')!='TEST_ONLY'
                or state.get('candidate_scope')!='isolated baseline schema and synthetic data'
                or state.get('candidate_phase') not in ('IMPORTING','NEEDS_INSPECTION')
                or state.get('primary_uuid')!=identity.SENTINEL):
            raise RuntimeError('run is not a live baseline import')
        def verify(label):
            raw=state.get('candidate_identities',{}).get(label)
            if not isinstance(raw,dict):raise RuntimeError('identity record absent')
            raw=dict(raw);raw['argv']=tuple(raw.get('argv',()))
            record=InstanceIdentity(**raw)
            return identity.guarded_verify({label:record},state,ctl.verify,rid,label,identity.SENTINEL,state['uuids'][label])
        verify('target')
        current=state.get('candidate_batch');committed=state.get('candidate_committed')
        if not isinstance(current,dict) or not isinstance(committed,list):raise RuntimeError('batch journal missing')
        uid=pwd.getpwnam('devops').pw_uid;base=Path('/var/tmp/ops-drill-kit');dst=base.lstat()
        if not stat.S_ISDIR(dst.st_mode) or dst.st_uid!=uid or stat.S_IMODE(dst.st_mode)!=0o700:
            raise RuntimeError('unsafe seed directory')
        batches=sorted((v[0],v[1],k,v[2]) for k,v in EXPECTED.items() if 'reference' not in k)
        prefix=hashlib.sha256();previous=0;matched=False
        for i,(first,end,name,sha) in enumerate(batches):
            if first!=previous+1:raise RuntimeError('non-contiguous manifest')
            data=checked(base/name,sha,8*1024*1024,uid,0o600)
            after=prefix.copy();after.update(data)
            item={'start':first,'end':end,'source_sha256':sha,
                  'before_sha256':prefix.hexdigest(),'after_sha256':after.hexdigest()}
            if i<len(committed):
                if committed[i]!=item:raise RuntimeError('committed journal mismatch')
            elif i==len(committed):
                if current!=item:raise RuntimeError('inflight journal mismatch')
                matched=True;break
            previous=end;prefix=after
        if not matched:raise RuntimeError('unexpected batch journal')
        socket=ctl.paths(rid,'target')[2]
        args=['/usr/bin/mysql','--no-defaults','--protocol=SOCKET','--socket='+str(socket),
              '--user=root','--batch','--raw','--skip-column-names']
        sql=(b'SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;\n'
             b'START TRANSACTION WITH CONSISTENT SNAPSHOT;\n'
             b'SELECT COUNT(*) FROM orderguard_stage3.orders;\n'
             b'SELECT order_no,merchant_id,user_id,order_status,amount_cents,pay_channel,created_at,updated_at '
             b'FROM orderguard_stage3.orders ORDER BY id;\nCOMMIT;\n')
        result=subprocess.run(args,input=sql,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                              timeout=180,env=ctl.ENV,check=False)
        if result.returncode or len(result.stdout)>64*1024*1024:raise RuntimeError('snapshot unavailable')
        count_text,sep,rows=result.stdout.partition(b'\n')
        if not sep or not re.fullmatch(rb'(?:0|[1-9][0-9]*)',count_text):raise RuntimeError('invalid count')
        count=int(count_text)
        if rows.count(b'\n')!=count:raise RuntimeError('snapshot count mismatch')
        verify('target')
        outcome=reconcile(instance_verified=True,start=current['start'],end=current['end'],
                          actual_count=count,actual_sha=hashlib.sha256(rows).hexdigest(),
                          expected_before_sha=current['before_sha256'],expected_after_sha=current['after_sha256'])
        print(json.dumps({'run_id':rid,'observation':outcome,'count':count}))
        return 0 if outcome in ('MATCHES_BEFORE_BATCH','MATCHES_AFTER_BATCH') else 2
    finally:
        os.close(fd)

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:
        print(json.dumps({'status':'NEEDS_INSPECTION','error_type':type(exc).__name__}),file=sys.stderr)
        sys.exit(2)
