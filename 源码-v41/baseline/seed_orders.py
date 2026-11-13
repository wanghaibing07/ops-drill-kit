#!/usr/bin/env python3
"""Prepare the fixed synthetic data files required by the Stage 3 import scripts."""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import os
from pathlib import Path
import pwd
import random
import stat
import subprocess
import sys
import tempfile

PROJECT=Path(__file__).resolve().parent.parent
GENERATOR=PROJECT/'scripts/generate_orders.py'
GENERATOR_SHA='c992a2017082890b7e78acdbb7c8928e5597eb3405de3e0e12808110c81337d2'
DATA=Path('/var/tmp/ops-drill-kit')
EXPECTED={
 'orders-500000-reference.tsv':(1,500000,'283a3a0453f2d1945ad33e81a0425ee4cf51bc59d8553bb2936901641f66993b'),
 'orders-50000-reference.tsv':(1,50000,'9d3b71e677e1b9619069cee1064ca04e61376baf096a3793ab78ce01f31f2e16'),
 'orders-1000-whole.tsv':(1,1000,'14ac915c8ce2abd0e18ef22ea1bf7ee0ecb4b92de4c478e501c3d38aa851e6c8'),
 'orders-1001-50000.tsv':(1001,50000,'8a33eb1e84cd9a960820fddf0c1c871e4e7f01845df6bd34e0cf9985082199bd'),
 'orders-50001-100000.tsv':(50001,100000,'6250d5f820ec542c716c59049d814415edb819237ce3020d1968b4fe8d798018'),
 'orders-100001-150000.tsv':(100001,150000,'74864abbf242561f3949e57d643cafa400493422b4d688de305b62b7c6a2240a'),
 'orders-150001-200000.tsv':(150001,200000,'f09bdd6a085133192b2544dd3a243f89a0bcbed35366dc2c40293d63fc3ae68c'),
 'orders-200001-250000.tsv':(200001,250000,'4725e7a48ae1b82ea929c0f7712964c15d8c2b9cb2c9c91caf1bdb1e32c50d96'),
 'orders-250001-300000.tsv':(250001,300000,'ce4c368103906b78961c0abedafab60b9a17aa04f861783381137f86d48d7313'),
 'orders-300001-350000.tsv':(300001,350000,'d42f276b7a35384bf2d8520d274387a40ca61eab40cbba57deeffadd36f3eb6f'),
 'orders-350001-400000.tsv':(350001,400000,'d27ae6c529685081cb15ef60866775c04cbfd3e3ea91d30818a7393ab8d288be'),
 'orders-400001-450000.tsv':(400001,450000,'ebe30c7015053d39295a27af4464827f5ad576aa62b77e50cbcbcae11862a5e0'),
 'orders-450001-500000.tsv':(450001,500000,'0d17cf15dee8f55be059f040da0bbd523202e731f40ad5e3d159cd20168ac31b')}


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def inspect(base,uid,expected):
    if not os.path.lexists(base):return list(expected)
    st=base.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=uid or stat.S_IMODE(st.st_mode)!=0o700:
        raise RuntimeError('unsafe data directory')
    if any(p.name.startswith('.seed-stage-') for p in base.iterdir()):
        raise RuntimeError('unfinished seed staging requires inspection')
    missing=[]
    for name,(_,_,sha) in expected.items():
        path=base/name
        if not os.path.lexists(path):missing.append(name);continue
        st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=uid or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or digest(path)!=sha:
            raise RuntimeError('existing seed file differs or is unsafe: '+name)
    return missing


def prepare(base,uid,expected,make_row,apply=False):
    missing=inspect(base,uid,expected)
    if not apply or not missing:return missing
    if not os.path.lexists(base):
        parent=base.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode):raise RuntimeError('unsafe data parent')
        base.mkdir(mode=0o700)
    if inspect(base,uid,expected)!=missing:raise RuntimeError('data directory changed')
    stage=Path(tempfile.mkdtemp(prefix='.seed-stage-',dir=base));os.chmod(stage,0o700)
    try:
        rng=random.Random(20261108)
        with ExitStack() as stack:
            streams={}
            for name in missing:
                fd=os.open(stage/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                streams[name]=stack.enter_context(os.fdopen(fd,'wb'))
            for number in range(1,max(v[1] for v in expected.values())+1):
                line=('\t'.join(str(x) for x in make_row(number,rng))+'\n').encode('utf8')
                for name in missing:
                    start,end,_=expected[name]
                    if start<=number<=end:streams[name].write(line)
            for f in streams.values():f.flush();os.fsync(f.fileno())
        for name in missing:
            if digest(stage/name)!=expected[name][2]:raise RuntimeError('generated seed digest mismatch: '+name)
        # Publish each verified file without replacing any existing path.
        for name in missing:
            os.link(stage/name,base/name,follow_symlinks=False)
            os.unlink(stage/name)
        os.rmdir(stage)
        stage=None
        fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        if inspect(base,uid,expected):raise RuntimeError('published seed set incomplete')
        return missing
    except BaseException:
        if stage is not None:print('Seed staging retained for inspection:',stage,file=sys.stderr)
        raise


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true',help='create only missing verified synthetic files')
    args=parser.parse_args(argv)
    try:
        uid=pwd.getpwnam('devops').pw_uid
        if os.geteuid()==0 or os.geteuid()!=uid:raise RuntimeError('run as devops, not root')
        marker=Path('/etc/opsdrill-lab');st=marker.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022 or st.st_size>64 or marker.read_bytes().strip()!=b'ops-drill-kit':
            raise RuntimeError('unsafe lab marker')
        cp=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],capture_output=True,text=True,timeout=10,check=False)
        if cp.returncode!=0 or cp.stdout.strip()!='vmware':raise RuntimeError('VMware lab required')
        st=GENERATOR.lstat()
        if not stat.S_ISREG(st.st_mode) or digest(GENERATOR)!=GENERATOR_SHA:raise RuntimeError('generator version mismatch')
        spec=importlib.util.spec_from_file_location('reviewed_seed_generator',GENERATOR)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        missing=prepare(DATA,uid,EXPECTED,module.make_row,args.apply)
        print(('created' if args.apply else 'would create'),len(missing),'of',len(EXPECTED),'synthetic files')
        return 0
    except (OSError,RuntimeError,ValueError) as exc:
        print('Seed preparation refused:',str(exc),file=sys.stderr)
        return 2


if __name__=='__main__':sys.exit(main())
