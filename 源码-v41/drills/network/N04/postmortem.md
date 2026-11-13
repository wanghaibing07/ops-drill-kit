# N04 实验复盘

执行者：agent；以下是隔离实验事实。

现象与处理：隔离网络命名空间的受限临时端口被短连接消耗；恢复端口范围并复用连接后请求成功。

证据：独立 run `2e841fdc0b522011a3773b4f` 观察到 TIME_WAIT 和 EADDRNOTAVAIL；CLI 另有实机契约。

边界：TCP 连接复用与 Nginx upstream keepalive 为不同实验，不能混为一谈。
