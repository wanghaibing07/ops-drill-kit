import importlib.util
import json
import pathlib
import unittest

here = pathlib.Path(__file__).resolve()
candidate = here.with_name('log_radar.py')
if not candidate.exists():
    candidate = here.parents[2] / 'scripts' / 'log_radar.py'
spec = importlib.util.spec_from_file_location('log_radar', candidate)
radar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(radar)


class RadarTests(unittest.TestCase):
    def test_combined_bad_and_empty(self):
        line = '192.0.2.4 - - [11/Nov/2026:11:10:10 +0000] "GET /orders?token=secret HTTP/1.1" 502 1 "-" "-"\n'
        result = radar.summarize([line, 'broken\n'])
        self.assertEqual((result['requests'], result['malformed']), (1, 1))
        self.assertEqual(result['status']['502']['count'], 1)
        self.assertEqual(result['top_networks'][0][0], '192.0.2.0/24')
        self.assertEqual(result['top_uri_paths'][0][0], '/orders')
        self.assertNotIn('secret', json.dumps(result))
        self.assertIsNone(result['latency_seconds']['p95'])
        self.assertEqual(radar.summarize([])['requests'], 0)

    def test_percentile_and_upstream_attempts(self):
        lines = [json.dumps({'status': 200, 'remote_addr': '2001:db8::1',
                 'request':'GET / HTTP/1.1', 'request_time':str(n),
                 'upstream_response_time':'0.01, 0.2'}) for n in range(1, 21)]
        result = radar.summarize(lines)
        self.assertEqual(result['latency_seconds']['p95'], 19.0)
        self.assertEqual(result['latency_seconds']['samples'], 20)
        self.assertEqual(result['upstream']['upstream_response_time']['multiple_attempts'], 20)

    def test_malformed_json_and_invalid_numeric(self):
        result = radar.summarize(['{bad', json.dumps({'status': 504, 'request_time':'NaN',
                                  'request': 'GET http://[ HTTP/1.1'})])
        self.assertEqual(result['malformed'], 1)
        self.assertEqual(result['latency_seconds']['samples'], 0)
        self.assertEqual(result['top_uri_paths'][0][0], 'UNKNOWN')

    def test_unknown_path_never_exposes_embedded_token(self):
        line = '192.0.2.4 - - [11/Nov/2026:11:10:10 +0000] "GET /secret/APIKEY HTTP/1.1" 200 1 "-" "-"'
        result = radar.summarize([line])
        self.assertNotIn('APIKEY', json.dumps(result))
        self.assertTrue(result['top_uri_paths'][0][0].startswith('path#'))


if __name__ == '__main__':
    unittest.main()
