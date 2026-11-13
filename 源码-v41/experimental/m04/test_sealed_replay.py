import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    sys.modules.setdefault('pwd', types.ModuleType('pwd'))
import sealed_replay as s

class SealedTests(unittest.TestCase):
    def test_failed_audit_does_not_create_replay_descriptor(self):
        with tempfile.TemporaryFile() as source:
            source.write(b'BEGIN; DELETE FROM orders;')
            source.flush()
            with patch.object(s.os, 'memfd_create', create=True) as create:
                with self.assertRaisesRegex(ValueError, 'reject'):
                    with s.sealed_stream(source.fileno(), lambda _: (_ for _ in ()).throw(ValueError('reject'))):
                        pass
                create.assert_not_called()

    def test_empty_stream_rejected(self):
        with tempfile.TemporaryFile() as source:
            with self.assertRaises(s.ctl.SafetyError):
                with s.sealed_stream(source.fileno(), lambda _: None):
                    pass

if __name__ == '__main__':
    unittest.main()
