import gzip
import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

here = pathlib.Path(__file__).resolve()
candidate = here.with_name('backup_verify.py')
if not candidate.exists(): candidate = here.parents[2] / 'scripts' / 'backup_verify.py'
spec = importlib.util.spec_from_file_location('backup_verify', candidate)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupTests(unittest.TestCase):
    def test_valid_and_corrupt_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp); data = gzip.compress(b'example')
            (p/'a.gz').write_bytes(data)
            (p/'SHA256SUMS').write_text(hashlib.sha256(data).hexdigest()+'  a.gz\n')
            self.assertEqual(backup.verify(tmp)['status'], 'PASS')
            (p/'a.gz').write_bytes(data[:-3])
            self.assertEqual(backup.verify(tmp)['status'], 'FAIL')

    def test_paths_and_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)
            (p/'SHA256SUMS').write_text('0'*64+'  ../elsewhere\n')
            with self.assertRaises(ValueError): backup.verify(tmp)
            (p/'a').symlink_to('/etc/passwd')
            (p/'SHA256SUMS').write_text('0'*64+'  a\n')
            self.assertEqual(backup.verify(tmp)['status'], 'FAIL')

    def test_duplicates_and_empty_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)
            (p/'SHA256SUMS').write_text('')
            with self.assertRaises(ValueError): backup.verify(tmp)
            (p/'a').write_bytes(b'x')
            line = hashlib.sha256(b'x').hexdigest()+'  a\n'
            (p/'SHA256SUMS').write_text(line+line)
            with self.assertRaises(ValueError): backup.verify(tmp)


if __name__ == '__main__': unittest.main()
