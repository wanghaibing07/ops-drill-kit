import importlib.util,os,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

root=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(root/'baseline'))
spec=importlib.util.spec_from_file_location('baseline_accounts',root/'baseline/accounts.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@unittest.skipUnless(hasattr(os,'geteuid') and os.geteuid()==0,'requires root-owned test files')
class AccountTests(unittest.TestCase):
    def test_empty_and_partial_states_are_distinguished(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths=(Path(tmp)/'app',Path(tmp)/'reader')
            with patch.object(m,'FILES',paths),patch.object(m,'admin',return_value=b'0\t0\t0\t0\t0\t5\t500000\t0\t0\n'):
                self.assertEqual(m.safety_and_state(),'create')
                paths[0].write_bytes(b'partial')
                with self.assertRaises(m.c.Refusal):m.safety_and_state()
            with patch.object(m,'FILES',paths),patch.object(m,'admin',return_value=b'1\t0\t0\t0\t0\t5\t500000\t0\t0\n'):
                with self.assertRaises(m.c.Refusal):m.safety_and_state()

    def test_create_is_exclusive_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);paths=(folder/'app',folder/'reader');values=[b'Aa1_'+b'x'*44,b'Bb2_'+b'y'*44]
            with patch.object(m,'FILES',paths),patch.object(m.c,'OPS',folder),patch.object(m,'generate_password',side_effect=values), \
                 patch.object(m,'admin',return_value=b'') as admin,patch.object(m,'check_existing') as verify:
                m.apply_create();verify.assert_called_once()
                self.assertIn(b'SET SESSION sql_log_bin=0',admin.call_args.args[0])
                self.assertEqual([p.read_bytes() for p in paths],values)
                self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in paths))
            with patch.object(m,'FILES',paths),patch.object(m.c,'OPS',folder),patch.object(m,'generate_password',return_value=b'Zz3_'+b'z'*44):
                with self.assertRaises(FileExistsError):m.apply_create()
            self.assertEqual([p.read_bytes() for p in paths],values)

    def test_password_generator_meets_policy(self):
        value=m.generate_password()
        self.assertEqual(len(value),48)
        self.assertTrue(any(65<=x<=90 for x in value))
        self.assertTrue(any(97<=x<=122 for x in value))
        self.assertTrue(any(48<=x<=57 for x in value))
        self.assertTrue(any(x in (45,95) for x in value))

    def test_login_escapes_password_in_memory_not_arguments(self):
        from types import SimpleNamespace
        secret=b'dummy "quote" \\ # value'
        def fake_run(args,**kwargs):
            self.assertFalse(any(secret.decode() in item for item in args))
            fd=kwargs['pass_fds'][0];os.lseek(fd,0,os.SEEK_SET)
            self.assertEqual(os.read(fd,512),b'[client]\npassword="dummy \\"quote\\" \\\\ # value"\n')
            return SimpleNamespace(returncode=0,stdout=b'orderguard_app@localhost\t5\n')
        with patch.object(m.subprocess,'run',side_effect=fake_run):m.login_probe('orderguard_app',secret)

if __name__=='__main__':unittest.main()
