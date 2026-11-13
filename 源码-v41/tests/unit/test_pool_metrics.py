import threading,unittest
from app.bounded_pool import BoundedPool,PoolClosed,PoolTimeout

class Connection:
 def __init__(self):self.bad_ping=False;self.bad_rollback=False;self.bad_close=False
 def ping(self,reconnect=False):
  if self.bad_ping:raise OSError('ping')
 def rollback(self):
  if self.bad_rollback:raise OSError('rollback')
 def close(self):
  if self.bad_close:raise OSError('close')

class MetricsTests(unittest.TestCase):
 def test_snapshot_counts_failures_and_generation(self):
  p=BoundedPool(Connection,1,.01);baseline=p.snapshot()
  with p.connection() as c:
   with self.assertRaises(PoolTimeout):
    with p.connection():pass
  with self.assertRaises(RuntimeError):
   with p.connection():raise RuntimeError('body')
  s=p.snapshot();self.assertEqual(s['generation'],baseline['generation']);self.assertGreater(s['monotonic_ns'],baseline['monotonic_ns'])
  self.assertEqual(s['errors']['timeout'],1);self.assertEqual(s['errors']['borrower'],1)
  s['errors']['timeout']=999;self.assertEqual(p.snapshot()['errors']['timeout'],1)
  p.close()
  with self.assertRaises(PoolClosed):
   with p.connection():pass
  self.assertEqual(p.snapshot()['errors']['closed'],1)
 def test_factory_rollback_and_close_failures_counted(self):
  p=BoundedPool(lambda:(_ for _ in ()).throw(OSError('factory')),1,.1)
  with self.assertRaises(OSError):
   with p.connection():pass
  self.assertEqual(p.snapshot()['errors']['factory'],1)
  p=BoundedPool(Connection,1,.1)
  with self.assertRaises(OSError):
   with p.connection() as c:c.bad_rollback=True;c.bad_close=True
  s=p.snapshot();self.assertEqual(s['errors']['rollback'],1);self.assertEqual(s['errors']['close'],1);self.assertEqual(s['quarantined'],1)
 def test_ping_error_then_replacement(self):
  p=BoundedPool(Connection,1,.1)
  with p.connection() as c:c.bad_ping=True
  with p.connection():pass
  self.assertEqual(p.snapshot()['errors']['ping'],1);p.close()
 def test_concurrent_errors_are_counted(self):
  p=BoundedPool(Connection,1,.01);threads=[]
  with p.connection():
   def waiter():
    try:
     with p.connection():pass
    except PoolTimeout:pass
   threads=[threading.Thread(target=waiter) for _ in range(4)]
   for t in threads:t.start()
   for t in threads:t.join(2);self.assertFalse(t.is_alive())
  self.assertEqual(p.snapshot()['errors']['timeout'],4);p.close()
if __name__=='__main__':unittest.main()
