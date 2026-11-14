import ast,contextlib,importlib.util,io,json,sys,types,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace())
spec=importlib.util.spec_from_file_location('m02_v2_cli',ROOT/'scripts/opsdrill_cli.py');cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
RID='a'*24;ATTEMPT='M02-20261113-123456'
def constant(path,name):
    tree=ast.parse(path.read_bytes());node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id==name for x in n.targets));return ast.literal_eval(node.value)
class M02VersionTests(unittest.TestCase):
    def args(self,command,version=None):return types.SimpleNamespace(command=command,variant=None,m02_version=version)
    def test_exact_baselines_are_distinct(self):
        self.assertEqual(constant(ROOT/'drills/mysql/M02/m02_deadlock.py','BASELINE'),{10086:3,10087:3})
        self.assertEqual(constant(ROOT/'drills/mysql/M02/baseline-v2/m02_deadlock.py','BASELINE'),{10086:2,10087:3})
    def test_v2_command_checks_v2_files(self):
        with mock.patch.object(cli,'m02_trusted_file') as checked:
            command=cli.m02_command('check',RID,version='baseline-v2')
        self.assertTrue(str(cli.M02_V2_INSTALL) in command[4]);self.assertEqual(checked.call_count,2)
    def test_start_records_version_before_invocation(self):
        writes=[];proc=types.SimpleNamespace(returncode=0,stdout=json.dumps({'receipt':'M02_DEADLOCK_OWNER_V1','run_id':RID}),stderr='')
        with mock.patch.object(cli.secrets,'token_hex',return_value=RID),mock.patch.object(cli,'allocate_id',return_value=ATTEMPT),mock.patch.object(cli,'event'),mock.patch.object(cli,'write_state',side_effect=lambda d,s:writes.append(dict(s))),mock.patch.object(cli,'m02_command',return_value=['cmd']) as command,mock.patch.object(cli.subprocess,'run',return_value=proc),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.m02_action(self.args('start','baseline-v2'),None,None),0)
        self.assertEqual(writes[0]['m02_version'],'baseline-v2');command.assert_called_once_with('inject',RID,version='baseline-v2')
    def test_mismatched_reset_version_refused_before_invocation(self):
        state={'run_id':RID,'attempt_id':ATTEMPT,'phase':'ACTIVE','m02_version':'baseline-v2'}
        with mock.patch.object(cli,'m02_command') as command,self.assertRaises(cli.Refused):cli.m02_action(self.args('reset','legacy'),state,RID)
        command.assert_not_called()
    def test_legacy_default_unchanged(self):
        with mock.patch.object(cli,'m02_trusted_file'):
            self.assertEqual(Path(cli.m02_command('check',RID)[4]).parent.name,'m02')
        with self.assertRaises(cli.Refused):cli.m02_command('check',RID,version='unknown')
    def test_check_parser_accepts_explicit_version(self):
        with mock.patch.object(cli,'action',return_value=0) as action:
            self.assertEqual(cli.main(['check','M02','--expect-run-id',RID,'--m02-version','baseline-v2']),0)
        self.assertEqual(action.call_args.args[0].m02_version,'baseline-v2')
if __name__=='__main__':unittest.main()
