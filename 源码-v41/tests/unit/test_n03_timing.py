import re
import unittest
from pathlib import Path

root = Path(__file__).resolve().parents[2]


class TimingConfigTests(unittest.TestCase):
    def test_only_approved_fields_are_logged(self):
        text = (root / 'conf/00-orderguard-timing.conf').read_text(encoding='utf-8')
        variables = set(re.findall(r'\$([A-Za-z_][A-Za-z_0-9]*)', text))
        self.assertEqual(variables, {'request_id', 'request_method', 'status', 'request_time',
                                     'upstream_connect_time', 'upstream_response_time'})
        self.assertIn('escape=json', text)

    def test_timing_log_is_separate_and_request_id_is_propagated(self):
        text = (root / 'conf/orderguard-nginx.conf').read_text(encoding='utf-8')
        self.assertIn('access_log /var/log/nginx/orderguard-access.log;', text)
        self.assertIn('access_log /var/log/nginx/orderguard-timing.log orderguard_timing;', text)
        self.assertIn('add_header X-Request-ID $request_id always;', text)
        self.assertIn('proxy_set_header X-Request-ID $request_id;', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
