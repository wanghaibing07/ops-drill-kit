import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import patch

source=pathlib.Path(__file__).resolve().parents[2]/'drills/linux/L03/l03_control.py'
spec=importlib.util.spec_from_file_location('l03_failed_unit',source)
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class FailedUnitTests(unittest.TestCase):
    def setUp(self):
        self.rid='c'*24
        self.unit='opsdrill-l03-'+self.rid+'.service'
        self.props={'LoadState':'loaded','ActiveState':'failed','ControlGroup':'',
                    'ExecStart':'{ path=%s ; argv[]=%s ; ignore_errors=no ; }' %
                                (m.PYTHON,' '.join(m.expected_argv(self.rid))),
                    'FragmentPath':'/run/systemd/transient/'+self.unit,
                    'Type':'exec','User':'','Group':'','InvocationID':''}

    def test_failed_matching_unit_is_reset(self):
        with patch.object(m,'sysctl',return_value=subprocess.CompletedProcess([],0)) as run, \
             patch.object(m,'unit_properties',return_value={'LoadState':'not-found','ControlGroup':''}):
            m.clear_failed_unit(self.unit,self.rid,self.props)
            run.assert_called_once_with('reset-failed',self.unit)

    def test_live_cgroup_or_mismatched_unit_is_never_reset(self):
        with patch.object(m,'sysctl') as run:
            props={**self.props,'ControlGroup':'/system.slice/'+self.unit}
            with self.assertRaisesRegex(m.Unsafe,'UNIT_CGROUP_BUSY'):
                m.clear_failed_unit(self.unit,self.rid,props)
            props={**self.props,'FragmentPath':'/other'}
            with self.assertRaisesRegex(m.Unsafe,'UNIT_FRAGMENT_MISMATCH'):
                m.clear_failed_unit(self.unit,self.rid,props)
            run.assert_not_called()

    def test_reset_failure_is_not_hidden(self):
        with patch.object(m,'sysctl',return_value=subprocess.CompletedProcess([],1)):
            with self.assertRaisesRegex(m.Unsafe,'UNIT_RESET_FAILED'):
                m.clear_failed_unit(self.unit,self.rid,self.props)


if __name__=='__main__':unittest.main()
