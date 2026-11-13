import importlib.util,json,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('report',Path(__file__).resolve().parents[2]/'scripts/report.py')
report=importlib.util.module_from_spec(spec);spec.loader.exec_module(report)
RID='a'*16
def e(kind,result,run=RID):
    d={'drill_id':'M04','attempt_id':'M04-20261113-123456','event':kind,'result':result,'actor':'agent'}
    if run is not None:d['run_id']=run
    return json.dumps(d)
class ReportTests(unittest.TestCase):
    def test_resolve_events_and_run_identity(self):
        result=report.summarize([e('inject','PASS'),e('resolve','STARTING'),e('resolve','PASS'),e('check','PASS')])
        self.assertEqual(result['invalid_lines'],0);self.assertEqual(result['attempts'][0]['run_id'],RID);self.assertEqual(result['attempts'][0]['status'],'PASS')
    def test_historical_missing_id_remains_unknown(self):
        result=report.summarize([e('inject','PASS',None),e('check','PASS',None)])
        self.assertIsNone(result['attempts'][0]['run_id']);self.assertEqual(result['attempts'][0]['status'],'PASS')
    def test_conflicting_or_partial_ids_are_invalid(self):
        for events in ([e('inject','PASS'),e('check','PASS','b'*16)],[e('inject','PASS'),e('check','PASS',None)]):
            row=report.summarize(events)['attempts'][0];self.assertEqual(row['status'],'INVALID');self.assertIsNone(row['run_id'])
    def test_malformed_id_rejected(self):
        self.assertEqual(report.summarize([e('inject','PASS','not-id')])['invalid_lines'],1)
if __name__=='__main__':unittest.main()
