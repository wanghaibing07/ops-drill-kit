import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('seed_orders',ROOT/'baseline/seed_orders.py')
seed=importlib.util.module_from_spec(spec);spec.loader.exec_module(seed)

def row(n,rng):return (str(n),str(n*2))
def lines(a,b):return ''.join(f'{n}\t{n*2}\n' for n in range(a,b+1)).encode()
def definitions():
    return {name:(a,b,hashlib.sha256(lines(a,b)).hexdigest()) for name,a,b in [('all.tsv',1,10),('early.tsv',1,3),('late.tsv',4,10)]}

class SeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)/'data';self.uid=os.geteuid();self.expected=definitions()
    def test_dry_run_and_repeat_are_non_overwriting(self):
        self.assertEqual(len(seed.prepare(self.base,self.uid,self.expected,row)),3)
        self.assertFalse(self.base.exists())
        self.assertEqual(len(seed.prepare(self.base,self.uid,self.expected,row,True)),3)
        before={p.name:p.stat().st_ino for p in self.base.iterdir()}
        self.assertEqual(seed.prepare(self.base,self.uid,self.expected,row,True),[])
        self.assertEqual(before,{p.name:p.stat().st_ino for p in self.base.iterdir()})
    def test_mismatch_refuses_before_creating_other_files(self):
        self.base.mkdir(mode=0o700);p=self.base/'all.tsv';p.write_bytes(b'other');p.chmod(0o600)
        with self.assertRaises(RuntimeError):seed.prepare(self.base,self.uid,self.expected,row,True)
        self.assertEqual(p.read_bytes(),b'other');self.assertFalse((self.base/'early.tsv').exists())
    def test_symlink_and_unfinished_staging_are_refused(self):
        self.base.mkdir(mode=0o700);(self.base/'all.tsv').symlink_to(self.base/'elsewhere')
        with self.assertRaises(RuntimeError):seed.inspect(self.base,self.uid,self.expected)
        (self.base/'all.tsv').unlink();(self.base/'.seed-stage-unfinished').mkdir()
        with self.assertRaises(RuntimeError):seed.inspect(self.base,self.uid,self.expected)
    def test_digest_mismatch_retains_staging_and_publishes_nothing(self):
        expected=dict(self.expected);a,b,_=expected['all.tsv'];expected['all.tsv']=(a,b,'0'*64)
        with self.assertRaises(RuntimeError):seed.prepare(self.base,self.uid,expected,row,True)
        self.assertFalse((self.base/'all.tsv').exists())
        self.assertEqual(len(list(self.base.glob('.seed-stage-*'))),1)

if __name__=='__main__':unittest.main()
