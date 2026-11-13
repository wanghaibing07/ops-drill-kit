import contextlib
import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

source = pathlib.Path(__file__).resolve().parents[2] / 'drills/linux/L03/l03_control.py'
spec = importlib.util.spec_from_file_location('l03_clean_control', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CleanCheckTests(unittest.TestCase):
    def test_healthy_no_unit_is_clean(self):
        with patch.object(module, 'sysctl', return_value=subprocess.CompletedProcess([],0,'')), \
             patch.object(module, 'health', return_value=True):
            self.assertEqual(module.clean_status(), 0)

    def test_orphan_unit_or_unhealthy_refuses_clean(self):
        with patch.object(module, 'sysctl', return_value=subprocess.CompletedProcess([],0,'orphan.service')):
            with self.assertRaisesRegex(module.Unsafe, 'ORPHAN_UNIT'): module.clean_status()
        with patch.object(module, 'sysctl', return_value=subprocess.CompletedProcess([],0,'')), \
             patch.object(module, 'health', return_value=False):
            with self.assertRaisesRegex(module.Unsafe, 'HEALTH_CHECK_FAILED'): module.clean_status()

    def test_missing_state_rejects_orphan_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            (base/'runs').mkdir(mode=0o700)
            (base/'runs'/'orphan').mkdir()
            rootfd = module.open_dir(str(base))
            runsfd = module.open_dir('runs', rootfd)
            with patch.object(module, 'check_lab'), patch.object(module, 'existing_root', return_value=(rootfd,runsfd)):
                with self.assertRaisesRegex(module.Unsafe, 'ORPHAN_RUNS'): module.inspect()


if __name__ == '__main__': unittest.main()
