import sys
import unittest
from unittest.mock import MagicMock,patch
if sys.platform=='win32': sys.modules.setdefault('fcntl',MagicMock())
import l02_watchdog_helper as h


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.rid='a'*24; self.inv='b'*32; self.boot='c'*36; self.sha='d'*64
        self.state={'version':1,'run_id':self.rid,'boot_id':self.boot,'phase':'REPAIRED',
                    'kind':'config-port-v1','invocation':self.inv,
                    'watchdog':{'timer':'opsdrill-l02-recover-'+self.rid+'.timer','helper_sha256':self.sha}}
        name='opsdrill-l02-'+self.rid+'.service'
        prefix='/etc/nginx/opsdrill-l02-isolated/'+self.rid+'/'
        self.props={'Id':name,'LoadState':'loaded','ActiveState':'active','Transient':'yes',
                    'FragmentPath':'/run/systemd/transient/'+name,'Type':'exec','User':'root',
                    'DropInPaths':'','InvocationID':self.inv,'ControlGroup':'/system.slice/'+name,
                    'ExecStart':'{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -p '+prefix+' -c nginx.conf -g daemon off; ; }'}

    def test_identity_requires_own_run_and_receipt(self):
        self.assertEqual(h.validate_state(self.state,self.rid,self.boot,self.sha),self.inv)
        for key,value in [('boot_id','wrong'),('kind','other'),('phase','unexpected')]:
            altered=dict(self.state); altered[key]=value
            with self.subTest(key=key),self.assertRaises(h.Refused): h.validate_state(altered,self.rid,self.boot,self.sha)
        with self.assertRaises(h.Refused): h.validate_state(self.state,self.rid,self.boot,'e'*64)

    def test_service_requires_invocation_and_exact_command(self):
        self.assertTrue(h.validate_service(self.rid,self.inv,self.props))
        for key in ('Id','InvocationID','Transient','FragmentPath','ExecStart','ControlGroup'):
            altered=dict(self.props); altered[key]='foreign'
            with self.subTest(key=key),self.assertRaises(h.Refused): h.validate_service(self.rid,self.inv,altered)
        self.assertFalse(h.validate_service(self.rid,self.inv,{'Id':self.props['Id'],'LoadState':'not-found'}))

    def test_recovery_stops_only_verified_service_and_preserves_state(self):
        after=dict(self.props,ActiveState='inactive',ControlGroup='')
        with patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
             patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
             patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=dict(self.state)), \
             patch.object(h,'properties',side_effect=[self.props,after]),patch.object(h,'command') as command, \
             patch.object(h,'save_state') as save,patch.object(h.os,'close'):
            path.return_value.read_text.return_value=self.boot
            h.recover(self.rid)
        command.assert_called_once_with('/usr/bin/systemctl','stop',self.props['Id'])
        saved=save.call_args.args[2]
        self.assertEqual(saved['phase'],'NEEDS_REVIEW')
        self.assertEqual(saved['watchdog_status'],'STOPPED_OR_ABSENT')
        self.assertIn('watchdog',saved)

    def test_refuses_changed_unit_without_stopping_or_saving(self):
        foreign=dict(self.props,InvocationID='e'*32)
        with patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
             patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
             patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=dict(self.state)), \
             patch.object(h,'properties',return_value=foreign),patch.object(h,'command') as command, \
             patch.object(h,'save_state') as save,patch.object(h.os,'close'):
            path.return_value.read_text.return_value=self.boot
            with self.assertRaises(h.Refused): h.recover(self.rid)
        command.assert_not_called(); save.assert_not_called()

    def test_missing_invocation_marks_review_without_stopping(self):
        state=dict(self.state,phase='PREPARED'); state.pop('invocation')
        with patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
             patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
             patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=state), \
             patch.object(h,'properties',return_value=self.props),patch.object(h,'command') as command, \
             patch.object(h,'save_state') as save,patch.object(h.os,'close'):
            path.return_value.read_text.return_value=self.boot
            with self.assertRaises(h.Refused): h.recover(self.rid)
        command.assert_not_called()
        saved=save.call_args.args[2]
        self.assertEqual(saved['phase'],'NEEDS_REVIEW')
        self.assertEqual(saved['watchdog_status'],'IDENTITY_UNVERIFIED')
        self.assertNotIn('invocation',saved)

    def test_missing_invocation_with_absent_service_records_absence(self):
        state=dict(self.state,phase='PREPARED'); state.pop('invocation')
        absent={'Id':self.props['Id'],'LoadState':'not-found'}
        with patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
             patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
             patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=state), \
             patch.object(h,'properties',return_value=absent),patch.object(h,'command') as command, \
             patch.object(h,'save_state') as save,patch.object(h.os,'close'):
            path.return_value.read_text.return_value=self.boot
            h.recover(self.rid)
        command.assert_not_called()
        self.assertEqual(save.call_args.args[2]['watchdog_status'],'STOPPED_OR_ABSENT')

    def test_prewrite_identity_is_persisted_before_stop(self):
        token='e'*32
        state=dict(self.state,phase='PREPARED',launch_intent={'version':1,'token':token}); state.pop('invocation')
        props=dict(self.props,Description='opsdrill-l02-launch-'+self.rid+'-'+token,Restart='no',NRestarts='0',RuntimeMaxUSec='2min')
        after=dict(props,ActiveState='inactive',ControlGroup='')
        calls=[]
        with patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
             patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
             patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=state), \
             patch.object(h,'properties',side_effect=[props,props,after]), \
             patch.object(h,'command',side_effect=lambda *a: calls.append(('stop',a))), \
             patch.object(h,'save_state',side_effect=lambda fd,rid,s: calls.append(('save',dict(s)))), \
             patch.object(h.os,'close'):
            path.return_value.read_text.return_value=self.boot
            h.recover(self.rid)
        self.assertEqual([c[0] for c in calls],['save','stop','save'])
        self.assertEqual(calls[0][1]['invocation'],self.inv)
        self.assertEqual(calls[0][1]['watchdog_status'],'OWNED_PREWRITE_VERIFIED')
        self.assertEqual(calls[-1][1]['watchdog_status'],'STOPPED_OR_ABSENT')

    def test_prewrite_rejects_restart_or_extra_command(self):
        token='e'*32
        props=dict(self.props,Description='opsdrill-l02-launch-'+self.rid+'-'+token,
                   Restart='no',NRestarts='0',RuntimeMaxUSec='2min')
        for key,value in [('Restart','always'),('NRestarts','1'),('RuntimeMaxUSec','infinity'),
                          ('ExecStart',props['ExecStart']+' { path=/other ; argv[]=/other ; }')]:
            changed=dict(props); changed[key]=value
            with self.subTest(key=key),self.assertRaises(h.Refused):
                h.validate_service(self.rid,self.inv,changed,token)

    def test_prewrite_collision_and_changed_invocation_never_stop(self):
        token='e'*32
        for variant in ('collision','changed'):
            state=dict(self.state,phase='PREPARED',launch_intent={'version':1,'token':token}); state.pop('invocation')
            props=dict(self.props,Description='opsdrill-l02-launch-'+self.rid+'-'+token,Restart='no',NRestarts='0',RuntimeMaxUSec='2min')
            if variant=='collision': props['Description']='foreign'
            changed=dict(props,InvocationID='f'*32)
            with self.subTest(variant=variant),patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
                 patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
                 patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=state), \
                 patch.object(h,'properties',side_effect=[props,changed]),patch.object(h,'command') as command, \
                 patch.object(h,'save_state') as save,patch.object(h.os,'close'):
                path.return_value.read_text.return_value=self.boot
                with self.assertRaises(h.Refused): h.recover(self.rid)
                command.assert_not_called()
                self.assertEqual(save.call_args.args[2]['watchdog_status'],'IDENTITY_UNVERIFIED')

    def test_prewrite_not_accepted_outside_prepared_phase(self):
        state=dict(self.state,phase='REPAIRED',launch_intent={'version':1,'token':'e'*32}); state.pop('invocation')
        with patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
             patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
             patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=state), \
             patch.object(h,'properties',return_value=self.props),patch.object(h,'command') as command, \
             patch.object(h,'save_state'),patch.object(h.os,'close'):
            path.return_value.read_text.return_value=self.boot
            with self.assertRaises(h.Refused): h.recover(self.rid)
            command.assert_not_called()

    def test_review_and_interrupted_prewrite_never_skip_marker(self):
        for status in ('IDENTITY_UNVERIFIED','OWNED_PREWRITE_VERIFIED'):
            state=dict(self.state,phase='NEEDS_REVIEW',watchdog_status=status,
                       launch_intent={'version':1,'token':'e'*32})
            foreign=dict(self.props,Description='foreign',Restart='no',NRestarts='0',RuntimeMaxUSec='2min')
            with self.subTest(status=status),patch.object(h,'guard'),patch.object(h,'secure_self',return_value=self.sha), \
                 patch.object(h,'Path') as path,patch.object(h,'journal_directory',return_value=10), \
                 patch.object(h,'acquire',return_value=11),patch.object(h,'read_state',return_value=state), \
                 patch.object(h,'properties',return_value=foreign),patch.object(h,'command') as command, \
                 patch.object(h,'save_state'),patch.object(h.os,'close'):
                path.return_value.read_text.return_value=self.boot
                with self.assertRaises(h.Refused): h.recover(self.rid)
                command.assert_not_called()


if __name__=='__main__': unittest.main()
