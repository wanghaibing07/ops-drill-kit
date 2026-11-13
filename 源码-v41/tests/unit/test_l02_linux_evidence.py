import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import os
import sys
import unittest
from l02_linux_evidence import listener_pids,proc_start_ticks,run_checked
from l02_policy import Refused

class EvidenceTests(unittest.TestCase):
    def test_proc_start_ticks_handles_spaces_and_parens(self):
        fields=['S']+['0']*18+['456']
        self.assertEqual(proc_start_ticks('42 (nginx (master process)) '+' '.join(fields)),456)
        with self.assertRaises(Refused): proc_start_ticks('broken')
    def test_listener_requires_loopback_and_pid(self):
        text='LISTEN 0 511 127.0.0.1:8443 0.0.0.0:* users:(("nginx",pid=42,fd=5))'
        self.assertEqual(listener_pids(text,8443),[42])
        with self.assertRaises(Refused): listener_pids(text,8080)
        with self.assertRaises(Refused): listener_pids(text.replace('pid=42','fd=5'),8443)

    @unittest.skipUnless(os.name=='posix','POSIX pipe selector required')
    def test_bounded_capture_and_stderr_drain(self):
        output=run_checked([sys.executable,'-c','import sys; sys.stderr.write("e"*100000); print("ok")'],limit=16)
        self.assertEqual(output,'ok\n')
        with self.assertRaises(Refused):
            run_checked([sys.executable,'-c','print("x"*100000)'],limit=16)
        with self.assertRaises(Refused):
            run_checked([sys.executable,'-c','raise SystemExit(7)'],limit=16)

if __name__=='__main__': unittest.main()
