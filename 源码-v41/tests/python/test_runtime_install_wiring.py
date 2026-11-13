import hashlib,importlib.util,sys,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace())
spec=importlib.util.spec_from_file_location('runtime_installer',ROOT/'baseline/install_drill_runtimes.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class WiringTests(unittest.TestCase):
    def test_pinned_runtime_sources_and_destinations(self):
        self.assertEqual(len(m.TASKS),12)
        self.assertEqual(len({x['target'] for x in m.TASKS}),12)
        for path,digest in m.PINS.items():
            with self.subTest(path=path):self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),digest)
        for task in m.TASKS:self.assertIn(task['installer'],m.PINS)
    def test_bootstrap_orders_dependencies_and_runtime_install(self):
        text=(ROOT/'baseline/bootstrap.py').read_text(encoding='utf8')
        for package in ('python3.11','python3.11-PyMySQL','python3.11-cryptography','python3.11-cffi','python3.11-pycparser'):self.assertIn("'"+package+"'",text)
        self.assertLess(text.index("('base_packages',"),text.index("('drill_runtimes',"))
        self.assertLess(text.index("('m04_v4',"),text.index("('drill_runtimes',"))
        self.assertLess(text.index("('drill_runtimes',"),text.index("('stack',"))
if __name__=='__main__':unittest.main()
