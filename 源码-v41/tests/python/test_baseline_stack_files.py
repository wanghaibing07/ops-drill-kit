import hashlib,importlib.util,os,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

root=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(root/'baseline'))
spec=importlib.util.spec_from_file_location('baseline_stack_files',root/'baseline/stack_files.py')
stack=importlib.util.module_from_spec(spec);spec.loader.exec_module(stack)

@unittest.skipUnless(hasattr(os,'geteuid') and os.geteuid()==0,'requires root-owned test files')
class StackFileTests(unittest.TestCase):
    def test_create_repeat_and_conflict_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);a=folder/'a';b=folder/'b'
            targets={str(a):(b'one\n',hashlib.sha256(b'one\n').hexdigest()),
                     str(b):(b'two\n',hashlib.sha256(b'two\n').hexdigest())}
            with patch.object(stack.c,'chain'):
                actions=stack.plan(targets);self.assertEqual(list(actions.values()),['create','create'])
                stack.create_only(targets,actions)
                self.assertEqual(list(stack.plan(targets).values()),['same','same'])
                b.write_bytes(b'changed\n');actions=stack.plan(targets)
                self.assertEqual(actions[str(b)],'conflict')
                with self.assertRaises(stack.c.Refusal):stack.create_only(targets,actions)
            self.assertEqual(a.read_bytes(),b'one\n');self.assertEqual(b.read_bytes(),b'changed\n')
            self.assertEqual(stat.S_IMODE(a.stat().st_mode),0o644)

    def test_race_and_symlink_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);p=folder/'file';content=b'expected'
            targets={str(p):(content,hashlib.sha256(content).hexdigest())}
            with patch.object(stack.c,'chain'):
                actions=stack.plan(targets);p.write_bytes(b'other')
                with self.assertRaises(FileExistsError):stack.create_only(targets,actions)
                self.assertEqual(p.read_bytes(),b'other')
                p.unlink();p.symlink_to(folder/'missing')
                with self.assertRaises(OSError):stack.plan(targets)

    def test_bundled_template_hashes_are_fixed(self):
        for content,digest in stack.TEMPLATES.values():
            self.assertEqual(hashlib.sha256(content).hexdigest(),digest)

if __name__=='__main__':unittest.main()
