import ast,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

class M02ContractOptionsTests(unittest.TestCase):
    def invoke(self,option):
        with tempfile.TemporaryDirectory() as name:
            tmp=Path(name);state=tmp/'state.json';records=tmp/'calls.jsonl';base=tmp/'evidence';base.mkdir()
            fake=tmp/'fake-cli'
            fake.write_text('''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]; state=Path(os.environ['TEST_STATE']); log=Path(os.environ['TEST_LOG']);rid='a'*24
with log.open('a') as f:f.write(json.dumps(args)+'\\n')
if args[0]=='start':
 state.write_text(json.dumps({'drill_id':'M02','run_id':rid,'phase':'ACTIVE'}));sys.exit(0)
expected=args[args.index('--expect-run-id')+1]
if expected!=rid:sys.exit(2)
if args[0]=='reset' and state.exists():state.unlink()
sys.exit(0)
''',encoding='utf8');fake.chmod(0o700)
            source=(ROOT/'tests/contract/M02.py').read_text(encoding='utf8')
            old="cli='/opt/ops-drill-kit/bin/opsdrill'";self.assertEqual(source.count(old),1);source=source.replace(old,'cli='+repr(str(fake)))
            old="state_path=Path('/var/lib/opsdrill/cli/M02.json')";self.assertEqual(source.count(old),1);source=source.replace(old,'state_path=Path('+repr(str(state))+')')
            old='stage=evidence_base()';self.assertEqual(source.count(old),1);source=source.replace(old,'stage=Path('+repr(str(base))+')')
            contract=tmp/'contract.py';contract.write_text(source,encoding='utf8')
            env=dict(os.environ,TEST_STATE=str(state),TEST_LOG=str(records))
            q=subprocess.run([sys.executable,'-B',str(contract),*option],capture_output=True,text=True,timeout=20,env=env)
            calls=[json.loads(x) for x in records.read_text().splitlines()] if records.exists() else []
            return q,calls
    def test_default_and_v2_are_forwarded_for_all_actions(self):
        for flags,expected in (([],'legacy'),(['--m02-version','baseline-v2'],'baseline-v2')):
            with self.subTest(version=expected):
                q,calls=self.invoke(flags);self.assertEqual(q.returncode,0,q.stderr);self.assertEqual(len(calls),7)
                self.assertTrue(all(c[c.index('--m02-version')+1]==expected for c in calls))
                self.assertTrue(all(c[c.index('--actor')+1]=='agent' for c in calls))
    def test_unknown_version_refused_before_any_action(self):
        q,calls=self.invoke(['--m02-version','unknown']);self.assertNotEqual(q.returncode,0);self.assertEqual(calls,[])
    @unittest.skipUnless(os.geteuid()==0,'requires root-owned parent')
    def test_evidence_directories_are_created_and_unsafe_paths_refused(self):
        tree=ast.parse((ROOT/'tests/contract/M02.py').read_text(encoding='utf8'))
        function=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='evidence_base')
        scope={'Path':Path,'os':os,'stat':__import__('stat')}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'contract','exec'),scope)
        with tempfile.TemporaryDirectory(dir=ROOT) as name:
            parent=Path(name);result=scope['evidence_base'](parent)
            self.assertEqual(result,parent/'backups/opsdrill/M02')
            self.assertEqual(scope['evidence_base'](parent),result)
        with tempfile.TemporaryDirectory(dir=ROOT) as name:
            parent=Path(name);(parent/'backups').symlink_to(parent,target_is_directory=True)
            with self.assertRaises(RuntimeError):scope['evidence_base'](parent)

if __name__=='__main__':unittest.main()
