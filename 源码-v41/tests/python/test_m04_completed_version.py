import importlib.util,json,os,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('m04_completed_version_cli',ROOT/'scripts/opsdrill_cli.py')
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
RID='a'*16

@unittest.skipUnless(os.geteuid()==0,'requires root-owned protected directory')
class CompletedVersionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.tmp.cleanup)
  self.path=Path(self.tmp.name)/'events.jsonl';self.patch=patch.object(cli,'EVENT_FILE',self.path);self.patch.start();self.addCleanup(self.patch.stop)
 def record(self,version='synthetic-v4',result='PASS',run=RID,attempt='M04-20261113-123456'):
  return {'drill_id':'M04','run_id':run,'attempt_id':attempt,'m04_version':version,'event':'reset','result':result}
 def write(self,rows):
  self.path.write_text(''.join(json.dumps(x)+'\n' for x in rows),encoding='utf8');os.chmod(self.path,0o600)
 def test_completed_version_and_missing_history(self):
  self.assertEqual(cli.completed_m04_version(RID),'synthetic-v1')
  for version in ('synthetic-v2','synthetic-v3','synthetic-v4'):
   self.write([self.record(version)]);self.assertEqual(cli.completed_m04_version(RID),version)
  self.write([self.record(run='b'*16)]);self.assertEqual(cli.completed_m04_version(RID),'synthetic-v1')
 def test_incomplete_or_ambiguous_history_refused(self):
  for rows in ([self.record(result='STARTING')],[self.record(),self.record(version='synthetic-v3')],[self.record(),self.record(attempt='M04-20261113-654321')]):
   self.write(rows)
   with self.subTest(rows=rows),self.assertRaises(cli.Refused):cli.completed_m04_version(RID)
 def test_unsafe_or_corrupt_history_refused(self):
  self.write([self.record()]);os.chmod(self.path,0o644)
  with self.assertRaises(cli.Refused):cli.completed_m04_version(RID)
  self.path.write_text('{"drill_id":"M04","drill_id":"M04"}\n');os.chmod(self.path,0o600)
  with self.assertRaises(cli.Refused):cli.completed_m04_version(RID)

if __name__=='__main__':unittest.main()
