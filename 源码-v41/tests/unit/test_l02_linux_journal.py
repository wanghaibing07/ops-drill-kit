import sys as _l02_sys
from pathlib import Path as _L02Path
_l02_root=_L02Path(__file__).resolve().parents[2]
_l02_sys.path.insert(0,str(_l02_root/'drills/linux/L02'))
_l02_sys.path.insert(0,str(_l02_root/'scripts'))
import os,tempfile,unittest,sys
from pathlib import Path
from unittest.mock import MagicMock
if sys.platform=='win32': sys.modules.setdefault('fcntl',MagicMock())
from l02_linux_journal import validate_record, unique, Journal
from l02_policy import Refused

class JournalTests(unittest.TestCase):
    def test_valid_record_and_run_binding(self):
        rid='a'*24; obj={'version':1,'run_id':rid,'phase':'FAULT','port':12345}
        self.assertTrue(validate_record(obj,rid).endswith(b'\n'))
        with self.assertRaises(Refused): validate_record(obj,'b'*24)
    def test_unknown_phase_and_duplicate_field(self):
        with self.assertRaises(Refused): validate_record({'version':1,'run_id':'a'*24,'phase':'UNKNOWN'},'a'*24)
        with self.assertRaises(Refused): unique([('x',1),('x',2)])
    def test_oversize_is_refused(self):
        with self.assertRaises(Refused): validate_record({'version':1,'run_id':'a'*24,'phase':'FAULT','blob':'x'*40000},'a'*24)

    @unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,'requires root on Linux')
    def test_real_journal_remove_requires_exact_record(self):
        rid='a'*24; obj={'version':1,'run_id':rid,'phase':'RESTORED'}
        with tempfile.TemporaryDirectory() as tmp:
            journal=object.__new__(Journal); journal.fd=os.open(tmp,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with journal.locked():
                    journal.save(rid,obj)
                    with self.assertRaises(Refused): journal.remove(rid,dict(obj,phase='FAULT'))
                    self.assertEqual(journal.read(rid),obj)
                    journal.remove(rid,obj)
                    self.assertIsNone(journal.read(rid))
            finally: journal.close()

if __name__=='__main__': unittest.main()
