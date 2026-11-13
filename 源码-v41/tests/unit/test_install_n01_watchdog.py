import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path('/opt/ops-drill-kit')
spec = importlib.util.spec_from_file_location('n01_installer', ROOT/'scripts/install_n01.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

@unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'requires a root-owned temporary installation directory')
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='opsdrill-n01-install-')
        self.path = Path(self.tmp.name)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        self.sources = {name: module.read_checked(str(ROOT/'drills/network/N01'/name), digest)
                        for name, digest in module.MANIFEST.items()}

    def tearDown(self):
        os.close(self.fd)
        self.tmp.cleanup()

    def test_fresh_and_idempotent(self):
        self.assertEqual(module.install_at(self.fd, self.sources), 2)
        self.assertEqual(module.install_at(self.fd, self.sources), 0)
        for name, data in self.sources.items():
            self.assertEqual((self.path/name).read_bytes(), data)

    def test_unknown_existing_controller_refused_before_helper_creation(self):
        (self.path/'n01.py').write_bytes(b'unknown')
        with self.assertRaises(module.Refused): module.install_at(self.fd, self.sources)
        self.assertFalse((self.path/'n01_watchdog.py').exists())
        self.assertEqual((self.path/'n01.py').read_bytes(), b'unknown')

    def test_symlink_refused(self):
        (self.path/'n01.py').symlink_to('/etc/passwd')
        with self.assertRaises(OSError): module.install_at(self.fd, self.sources)
        self.assertFalse((self.path/'n01_watchdog.py').exists())

if __name__ == '__main__': unittest.main()
