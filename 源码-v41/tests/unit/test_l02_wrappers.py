import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
class L02EntryTests(unittest.TestCase):
    def test_all_standard_wrappers_forward_flags_to_unified_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);dest=root/'drills/linux/L02';dest.mkdir(parents=True)
            (root/'bin').mkdir()
            cli=root/'bin/opsdrill'
            cli.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n',encoding='utf8')
            os.chmod(cli,0o755)
            for filename,action in (('inject.sh','start'),('check.sh','check'),('reset.sh','reset')):
                shutil.copyfile(ROOT/'drills/linux/L02'/filename,dest/filename)
                result=subprocess.run(['/bin/bash',str(dest/filename),'--actor','agent'],capture_output=True,text=True,check=True)
                self.assertEqual(json.loads(result.stdout),[action,'L02','--actor','agent'])

if __name__=='__main__':unittest.main()
