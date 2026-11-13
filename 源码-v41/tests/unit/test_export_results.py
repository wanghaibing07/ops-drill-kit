import importlib.util
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

module_path=Path(__file__).resolve().parents[2]/'scripts/export_results.py'
spec=importlib.util.spec_from_file_location('export_results',module_path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.result=self.root/'results.md';self.history=self.root/'results-m02-history.md'
        for name,value in (('RESULT',self.result),('HISTORY',self.history)):
            p=mock.patch.object(m,name,value);p.start();self.addCleanup(p.stop)
    def test_preserves_handwritten_bytes_and_updates_only_generated_file(self):
        original='旧记录\r\n'.encode('utf8');self.result.write_bytes(original)
        with self.assertRaises(RuntimeError):m.write_result(m.MARKER+'# 演练结果\n')
        self.assertEqual(self.result.read_bytes(),original)
        m.write_result(m.MARKER+'# 演练结果\n',True)
        self.assertEqual(self.history.read_bytes(),original)
        self.assertIn('历史记录',self.result.read_text(encoding='utf8'))
        m.write_result(m.MARKER+'# 演练结果\nnew\n')
        self.assertEqual(self.history.read_bytes(),original)
    def test_refuses_symlink_and_does_not_touch_target(self):
        other=self.root/'other';other.write_text('unchanged',encoding='utf8')
        self.result.symlink_to(other)
        with self.assertRaises(RuntimeError):m.write_result(m.MARKER+'# 演练结果\n',True)
        self.assertEqual(other.read_text(encoding='utf8'),'unchanged')
    def test_event_file_protection_and_generated_content(self):
        events=self.root/'events.jsonl';events.write_text('{}\n');events.chmod(0o600)
        real_fstat=os.fstat
        def root_owned(fd):
            st=real_fstat(fd)
            return types.SimpleNamespace(st_mode=st.st_mode,st_uid=0,st_nlink=st.st_nlink)
        with mock.patch.object(m,'EVENTS',events),mock.patch.object(m.os,'fstat',side_effect=root_owned),mock.patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(stdout='# 演练结果\n\nactor agent\n')):
            text=m.render()
        self.assertTrue(text.startswith(m.MARKER));self.assertIn('actor agent',text)
        events.chmod(0o644)
        with mock.patch.object(m,'EVENTS',events),mock.patch.object(m.os,'fstat',side_effect=root_owned),self.assertRaises(RuntimeError):m.render()

if __name__=='__main__':unittest.main()
