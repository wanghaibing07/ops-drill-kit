import unittest
from fastapi import HTTPException
from starlette.requests import Request
from app import main,stage3_api
from app.bounded_pool import BoundedPool

def request(host='127.0.0.1',headers=()):
 return Request({'type':'http','method':'GET','path':'/__opsdrill/pool-metrics','headers':list(headers),'client':(host,12345),'server':('127.0.0.1',8000),'scheme':'http','query_string':b''})

class EndpointTests(unittest.TestCase):
 def setUp(self):
  self.old=(main._pool,stage3_api._pool);main._pool=BoundedPool(lambda:None,1,1);stage3_api._pool=BoundedPool(lambda:None,1,1)
 def tearDown(self):main._pool,stage3_api._pool=self.old
 def test_local_request_has_only_bounded_counts(self):
  result=main.pool_metrics(request());self.assertEqual(result['scope'],'single-process-lab')
  self.assertGreater(result['pid'],0);self.assertEqual(result['legacy']['capacity'],1);self.assertEqual(result['stage3']['capacity'],1)
  self.assertEqual(set(result['legacy']['errors']),{'closed','timeout','factory','ping','rollback','close','borrower'})
 def test_forwarded_and_nonlocal_requests_are_denied(self):
  for req in (request('192.0.2.1'),request(headers=[(b'x-forwarded-for',b'127.0.0.1')])):
   with self.assertRaises(HTTPException) as e:main.pool_metrics(req)
   self.assertEqual(e.exception.status_code,404)
 def test_unavailable_pool_is_explicit(self):
  main._pool=None;self.assertIsNone(main.pool_metrics(request())['legacy'])
if __name__=='__main__':unittest.main()
