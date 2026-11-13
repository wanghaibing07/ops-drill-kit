import json,socket,threading,time,unittest,urllib.error,urllib.request
import uvicorn
from app import main,stage3_api
from app.bounded_pool import BoundedPool

class HTTPTests(unittest.TestCase):
 def test_loopback_metrics_and_forwarded_denial(self):
  old=(main._pool,stage3_api._pool)
  def fail():raise OSError('synthetic test failure')
  main._pool=BoundedPool(fail,1,.1);stage3_api._pool=BoundedPool(fail,1,.1)
  sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen(8);port=sock.getsockname()[1]
  config=uvicorn.Config(main.app,host='127.0.0.1',port=port,log_level='critical',lifespan='off');server=uvicorn.Server(config)
  thread=threading.Thread(target=lambda:server.run(sockets=[sock]),daemon=True);thread.start()
  try:
   deadline=time.monotonic()+5
   while not server.started and time.monotonic()<deadline:time.sleep(.02)
   self.assertTrue(server.started);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));url='http://127.0.0.1:'+str(port)+'/__opsdrill/pool-metrics'
   with opener.open(url,timeout=3) as response:before=json.load(response)
   with self.assertRaises(OSError):
    with main._pool.connection():pass
   with opener.open(url,timeout=3) as response:after=json.load(response)
   self.assertEqual(before['pid'],after['pid']);self.assertEqual(before['legacy']['generation'],after['legacy']['generation'])
   self.assertEqual(after['legacy']['errors']['factory']-before['legacy']['errors']['factory'],1)
   with self.assertRaises(urllib.error.HTTPError) as rejected:opener.open(urllib.request.Request(url,headers={'X-Forwarded-For':'192.0.2.1'}),timeout=3)
   self.assertEqual(rejected.exception.code,404)
  finally:
   server.should_exit=True;thread.join(5);sock.close();main._pool,stage3_api._pool=old
  self.assertFalse(thread.is_alive())
if __name__=='__main__':unittest.main()
