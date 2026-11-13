"""Run restored app files with disposable database connection factories."""
import os,socket,sys
sys.path.insert(0,os.environ['M04_APP_SOURCE'])
import pymysql,uvicorn
from app import main,stage3_api

def connection():
 return pymysql.connect(unix_socket=os.environ['M04_PROXY_SOCKET'],user=os.environ['M04_TEST_USER'],
     password=os.environ['M04_TEST_MARKER'],database='orderguard_restore_m04',charset='utf8mb4',
     cursorclass=pymysql.cursors.DictCursor,connect_timeout=3,read_timeout=5,write_timeout=5)
main._new_db_connection=connection
stage3_api._new_stage3_connection=connection
sock=socket.socket(fileno=int(os.environ['M04_HTTP_FD']))
uvicorn.Server(uvicorn.Config(main.app,host='127.0.0.1',log_config=None,access_log=False,workers=1)).run(sockets=[sock])
