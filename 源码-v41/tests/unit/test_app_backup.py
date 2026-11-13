import importlib.util
from pathlib import Path
import tempfile
import unittest

local_tool = Path(__file__).with_name('app_backup.py')
project_tool = Path(__file__).resolve().parents[2] / 'scripts' / 'app_backup.py'
spec = importlib.util.spec_from_file_location('app_backup', local_tool if local_tool.exists() else project_tool)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.lab = Path(self.temp.name)
        (self.lab / '.opsdrill-lab').write_text('ops-drill-kit', encoding='utf-8')
        (self.lab / 'app' / 'config').mkdir(parents=True)
        (self.lab / 'app' / 'config' / 'a').write_bytes(b'abc\x00')
        (self.lab / 'backups').mkdir(); (self.lab / 'restores').mkdir()
    def tearDown(self): self.temp.cleanup()
    def test_round_trip(self):
        m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        m.restore(self.lab, 'backups/run', 'restores/run')
        self.assertEqual((self.lab/'restores/run/config/a').read_bytes(), b'abc\x00')
    def test_reject_traversal_and_duplicate(self):
        for path in ('../other', '/etc/passwd', 'config/../a', 'config\\a', 'C:/data'):
            with self.subTest(path=path), self.assertRaises(ValueError): m.validate_list([path])
        with self.assertRaises(ValueError): m.validate_list(['config/a', 'config/a'])
    def test_no_overwrite_and_overlap(self):
        m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        with self.assertRaises(FileExistsError): m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        with self.assertRaises(ValueError): m.backup(self.lab, 'app', 'app/run', ['config/a'])
        self.assertEqual((self.lab/'backups/run/config/a').read_bytes(), b'abc\x00')
    def test_tamper_keeps_failed_evidence(self):
        m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        (self.lab/'backups/run/config/a').write_bytes(b'altered')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'): m.restore(self.lab, 'backups/run', 'restores/run')
        self.assertEqual((self.lab/'restores/run/config/a').read_bytes(), b'altered')
        self.assertTrue((self.lab/'backups/run/manifest.json').exists())
    def test_symlink_rejected(self):
        link = self.lab/'app/config/link'
        try: link.symlink_to(self.lab/'app/config/a')
        except (OSError, NotImplementedError): self.skipTest('symlinks unavailable')
        with self.assertRaises(ValueError): m.backup(self.lab, 'app', 'backups/run', ['config/link'])
        self.assertTrue((self.lab/'backups/run').is_dir())
    @unittest.skipIf(__import__('os').name == 'nt', 'Windows chmod cannot express POSIX execute bits')
    def test_executable_permissions_round_trip_without_special_bits(self):
        import os, stat, json
        source = self.lab/'app/config/a'
        os.chmod(source, 0o4751)
        m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        doc = json.loads((self.lab/'backups/run/manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(doc['files'][0]['mode'], 0o751)
        m.restore(self.lab, 'backups/run', 'restores/run')
        self.assertEqual(stat.S_IMODE((self.lab/'restores/run/config/a').stat().st_mode), 0o751)
    def test_source_change_fails_and_preserves_partial_output(self):
        from unittest.mock import patch
        real = m.file_state
        count = 0
        def changing(st):
            nonlocal count
            count += 1
            state = real(st)
            return state if count == 1 else state[:2] + (state[2] + 1,) + state[3:]
        with patch.object(m, 'file_state', changing):
            with self.assertRaisesRegex(ValueError, 'source changed'):
                m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        self.assertTrue((self.lab/'backups/run/config/a').exists())
        self.assertFalse((self.lab/'backups/run/manifest.json').exists())
    def test_restored_mode_is_verified(self):
        from unittest.mock import patch
        m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        with patch.object(m.os, 'chmod', lambda *args: None):
            with patch.object(m.stat, 'S_IMODE', return_value=0):
                with self.assertRaisesRegex(ValueError, 'restore mode mismatch'):
                    m.restore(self.lab, 'backups/run', 'restores/run')
    def test_marker_required(self):
        (self.lab / '.opsdrill-lab').unlink()
        with self.assertRaises(OSError): m.backup(self.lab, 'app', 'backups/run', ['config/a'])
    def test_link_mode_rejected(self):
        from unittest.mock import patch
        real = Path.lstat
        class LinkStat:
            st_mode = 0o120777
            st_file_attributes = 0
        with patch.object(Path, 'lstat', lambda p: LinkStat() if p.name == 'a' else real(p)):
            with self.assertRaises(ValueError): m.backup(self.lab, 'app', 'backups/run', ['config/a'])
    def test_corrupt_manifest_rejected_before_destination(self):
        m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        manifest = self.lab/'backups/run/manifest.json'
        for body in ('{"version":true,"files":[]}', '{"version":1,"version":1,"files":[]}',
                     '{"version":1,"files":[{"path":"x","sha256":"' + '0'*64 + '","mode":true}]}'):
            with self.subTest(body=body):
                manifest.write_text(body, encoding='utf-8')
                with self.assertRaises(ValueError): m.restore(self.lab, 'backups/run', 'restores/run')
                self.assertFalse((self.lab/'restores/run').exists())
    @unittest.skipIf(__import__('os').name == 'nt', 'POSIX permissions required')
    def test_backup_private_and_restrictive_mode_restore(self):
        import os, stat
        source = self.lab/'app/config/a'
        os.chmod(source, 0o400)
        m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        self.assertEqual(stat.S_IMODE((self.lab/'backups/run/config/a').stat().st_mode), 0o600)
        m.restore(self.lab, 'backups/run', 'restores/run')
        self.assertEqual(stat.S_IMODE((self.lab/'restores/run/config/a').stat().st_mode), 0o400)
    def test_manifest_traversal_rejected(self):
        import json
        m.backup(self.lab, 'app', 'backups/run', ['config/a'])
        (self.lab/'backups/run/manifest.json').write_text(json.dumps({'version':1,'files':[{'path':'../bad','sha256':'0'*64,'mode':420}]}), encoding='utf-8')
        with self.assertRaises(ValueError): m.restore(self.lab, 'backups/run', 'restores/run')
        self.assertFalse((self.lab/'restores/run').exists())

if __name__ == '__main__': unittest.main()
