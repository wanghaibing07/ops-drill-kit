"""Launch the actual app with only its DB factory adapted to a disposable socket."""
import os,socket,sys
sys.path.insert(0,os.environ['M03_APP_SOURCE'])
import pymysql,uvicorn
from app import main

def synthetic_connection():
 return pymysql.connect(unix_socket=os.environ['M03_PROXY_SOCKET'],user=os.environ['M03_PUBLIC_USER'],
    password=os.environ['M03_PUBLIC_MARKER'],charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor,
    connect_timeout=3,read_timeout=5,write_timeout=5)
main._new_db_connection=synthetic_connection
fd=int(os.environ['M03_HTTP_FD']);sock=socket.socket(fileno=fd)
config=uvicorn.Config(main.app,host='127.0.0.1',log_config=None,access_log=False,workers=1)
uvicorn.Server(config).run(sockets=[sock])
