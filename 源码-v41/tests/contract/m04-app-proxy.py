"""Bounded peer-restricted relay to one identity-pinned test socket."""
import os,select,socket,stat,struct,sys,threading,time

listen,target,device,inode,uid,gid=sys.argv[1:]
device,inode,uid,gid=map(int,(device,inode,uid,gid))
assert not os.path.lexists(listen)
slots=threading.BoundedSemaphore(4)
deadline=time.monotonic()+300

def transfer(client):
 try:
  with client:
   _,peer_uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
   if peer_uid!=uid:return
   st=os.lstat(target)
   if not stat.S_ISSOCK(st.st_mode) or (st.st_dev,st.st_ino)!=(device,inode):return
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as upstream:
    upstream.settimeout(5);upstream.connect(target);upstream.settimeout(None)
    pair=(client,upstream)
    while time.monotonic()<deadline:
     ready,_,_=select.select(pair,[],[],1)
     for src in ready:
      data=src.recv(65536)
      if not data:return
      (upstream if src is client else client).sendall(data)
 except (OSError,ValueError):pass
 finally:slots.release()

with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
 server.bind(listen);os.chown(listen,0,gid);os.chmod(listen,0o660);server.listen(4);server.settimeout(1)
 while time.monotonic()<deadline:
  try:client,_=server.accept()
  except socket.timeout:continue
  if not slots.acquire(blocking=False):client.close();continue
  threading.Thread(target=transfer,args=(client,),daemon=True).start()
