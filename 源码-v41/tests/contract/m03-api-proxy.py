"""One-run, peer-restricted relay to an identity-pinned isolated Unix socket."""
import os,select,socket,stat,struct,sys,time

listen,target,device,inode,uid,gid=sys.argv[1:]
device,inode,uid,gid=map(int,(device,inode,uid,gid))
assert not os.path.lexists(listen)
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
 server.bind(listen);os.chown(listen,0,gid);os.chmod(listen,0o660);server.listen(4);server.settimeout(1)
 deadline=time.monotonic()+240
 while time.monotonic()<deadline:
  try:client,_=server.accept()
  except socket.timeout:continue
  with client:
   _,peer_uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
   if peer_uid!=uid:continue
   st=os.lstat(target)
   if not stat.S_ISSOCK(st.st_mode) or (st.st_dev,st.st_ino)!=(device,inode):raise RuntimeError('target socket identity changed')
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as upstream:
    upstream.settimeout(4);upstream.connect(target);upstream.settimeout(None)
    streams=(client,upstream)
    while time.monotonic()<deadline:
     ready,_,_=select.select(streams,[],[],1)
     if not ready:continue
     closed=False
     for src in ready:
      data=src.recv(65536)
      if not data:closed=True;break
      (upstream if src is client else client).sendall(data)
     if closed:break
