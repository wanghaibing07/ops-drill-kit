# 提示

先在 od-client 查看路由，再核对 od-router 的 inet od 表，分别在客户端侧和服务端侧观察 SYN、SYN-ACK。服务端没有常驻监听器时，应使用 N02 check 自带的短时监听器；单凭 ping 或单次连接失败不能判断 ACL。
