import importlib.util
import json
import pathlib
import unittest

here=pathlib.Path(__file__).resolve()
candidate=here.with_name('report.py')
if not candidate.exists(): candidate=here.parents[2]/'scripts'/'report.py'
spec=importlib.util.spec_from_file_location('opsdrill_report',candidate)
report=importlib.util.module_from_spec(spec); spec.loader.exec_module(report)


class ReportTests(unittest.TestCase):
    def test_empty_and_bad_lines(self):
        self.assertEqual(report.summarize([])['attempts'],[])
        self.assertEqual(report.summarize(['bad\n'])['invalid_lines'],1)

    def test_user_times_only_with_matching_monotonic_clock(self):
        def event(kind, ns, **extra):
            return {'drill_id':'L01','attempt_id':'L01-20261112-001','event':kind,'actor':'user',
                    'boot_id':'one','monotonic_ns':ns,**extra}
        events=[event('inject',1_000_000_000,result='PASS'),event('diagnosis',3_000_000_000),
                event('check',4_000_000_000,result='FAIL'),event('check',7_000_000_000,result='PASS')]
        row=report.summarize(map(json.dumps,events))['attempts'][0]
        self.assertEqual((row['status'],row['nonzero_checks']),('PASS',1))
        self.assertEqual((row['mttd_proxy_seconds'],row['mttr_proxy_seconds']),(2.0,6.0))
        events[-1]['boot_id']='other'
        self.assertIsNone(report.summarize(map(json.dumps,events))['attempts'][0]['mttr_proxy_seconds'])

    def test_automation_timing_keeps_actor_and_rejects_mixed_actors(self):
        a={'drill_id':'M01','attempt_id':'M01-20261112-002','event':'inject','result':'PASS',
           'actor':'agent','boot_id':'b','monotonic_ns':1_000_000_000}
        b={**a,'event':'check','monotonic_ns':3_000_000_000}
        row=report.summarize(map(json.dumps,[a,b]))['attempts'][0]
        self.assertEqual((row['actor'],row['mttr_proxy_seconds']),('agent',2.0))
        b['actor']='user'
        self.assertIsNone(report.summarize(map(json.dumps,[a,b]))['attempts'][0]['mttr_proxy_seconds'])

    def test_incomplete_injection_actor_requires_consensus(self):
        start={'drill_id':'M04','attempt_id':'M04-20261112-364997','event':'inject',
               'result':'STARTING','actor':'agent','boot_id':'b','monotonic_ns':1}
        failed={**start,'result':'FAIL','monotonic_ns':2}
        row=report.summarize(map(json.dumps,[start,failed]))['attempts'][0]
        self.assertEqual((row['actor'],row['status']),('agent','INCOMPLETE'))
        self.assertIsNone(row['mttd_proxy_seconds'])
        self.assertIsNone(row['mttr_proxy_seconds'])
        failed['actor']='user'
        self.assertEqual(report.summarize(map(json.dumps,[start,failed]))['attempts'][0]['actor'],'unknown')
        del failed['actor']
        self.assertEqual(report.summarize(map(json.dumps,[start,failed]))['attempts'][0]['actor'],'unknown')
        failed['actor']=['agent']
        self.assertEqual(report.summarize(map(json.dumps,[start,failed]))['attempts'][0]['actor'],'unknown')

    def test_check_before_inject_is_not_a_success(self):
        check={'drill_id':'L01','attempt_id':'L01-20261112-003','event':'check','result':'PASS'}
        start={**check,'event':'inject'}
        self.assertEqual(report.summarize(map(json.dumps,[check,start]))['attempts'][0]['status'],'INCOMPLETE')

    def test_later_failure_and_duplicate_start_are_not_hidden(self):
        a={'drill_id':'L01','attempt_id':'L01-20261112-004','event':'inject','result':'PASS'}
        p={**a,'event':'check'}
        f={**p,'result':'FAIL'}
        self.assertEqual(report.summarize(map(json.dumps,[a,p,f]))['attempts'][0]['status'],'FAIL')
        self.assertEqual(report.summarize(map(json.dumps,[a,a,p]))['attempts'][0]['status'],'INVALID')


if __name__=='__main__': unittest.main()
