## 手动为容器添加bridge网络

1. 准备工作，创建容器
```shell
# 创建容器
$ isula run -tid busybox sh
2b6daf278a79b3de03c2674ca4fac3ae540339fe214db739dd5cfc1e73146fea
# 获取容器pid
$ isula inspect 2b6daf27 | grep -i pid
            "Pid": 6064,
            "PidMode": "",
            "PidsLimit": 0,
```

2. 创建网桥
```shell
# 创建网桥
$ ip link add my-bridge type bridge
# 开启网桥设备
$ ip link set my-bridge up
```

3. 创建veth设备
```shell
# 创建veth设备对，一端在host，一端在container
$ ip link add veth-host type veth peer name veth-container netns 6064
# 开启设备
$ ip link set veth-host up
$ nsenter -t 6064 -n ip link set veth-container up
# host一端veth加入bridge
$ ip link set dev veth-host master my-bridge
```

4. 设置网络IP，网段为192.175.0.0/24
```shell
# 设置my-bridge ip地址，同时也会在host上增加192.175.0.0/24网段的路由
$ ip addr add 192.175.0.1/24 dev my-bridge
# 设置容器内ip地址
$ nsenter -t 6064 -n ip addr add 192.175.0.2/24 dev veth-container
# 设置容器内路由
$ nsenter -t 6064 -n ip route add default via 192.175.0.1 dev veth-container


# host ping container ip
$ ping -c 3 192.175.0.2
PING 192.175.0.2 (192.175.0.2) 56(84) bytes of data.
64 bytes from 192.175.0.2: icmp_seq=1 ttl=64 time=0.118 ms
64 bytes from 192.175.0.2: icmp_seq=2 ttl=64 time=0.172 ms
64 bytes from 192.175.0.2: icmp_seq=3 ttl=64 time=0.414 ms

--- 192.175.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2065ms
rtt min/avg/max/mdev = 0.118/0.234/0.414/0.128 ms

# container ping host bridge
$ nsenter -t 6064 -n ping -c 3 192.175.0.1
PING 192.175.0.1 (192.175.0.1) 56(84) bytes of data.
64 bytes from 192.175.0.1: icmp_seq=1 ttl=64 time=0.247 ms
64 bytes from 192.175.0.1: icmp_seq=2 ttl=64 time=0.189 ms
64 bytes from 192.175.0.1: icmp_seq=3 ttl=64 time=0.251 ms

--- 192.175.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2052ms
rtt min/avg/max/mdev = 0.189/0.229/0.251/0.028 ms

# container ping host eth
$ nsenter -t 6064 -n ping -c 3 172.26.110.110
PING 172.26.110.110 (172.26.110.110) 56(84) bytes of data.
64 bytes from 172.26.110.110: icmp_seq=1 ttl=64 time=0.237 ms
64 bytes from 172.26.110.110: icmp_seq=2 ttl=64 time=0.105 ms
64 bytes from 172.26.110.110: icmp_seq=3 ttl=64 time=0.100 ms

--- 172.26.110.110 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2111ms
rtt min/avg/max/mdev = 0.100/0.147/0.237/0.063 ms
```

但此时容器ping host之外的ip地址，发现是无法ping通的
```shell
$ nsenter -t 6064 -n ping -c 3 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2115ms
```

5. 开启ip forward，网络地址转换
- IP forwad，也就是所谓的转发，即当主机拥有多于一块的网卡时，其中一块收到数据包，根据数据包的目的ip地址将包发往本机另一网卡，该网卡根据路由表继续发送数据包。这通常就是路由器所要实现的功能。
```shell
# host测设置开启forward
$ sysctl -w net.ipv4.ip_forward=1
# iptables中filter表的FORWARD链，默认的policy是DROP，添加规则对my-bridge开启
$ iptables -A FORWARD -o my-bridge -j ACCEPT
$ iptables -A FORWARD -i my-bridge -j ACCEPT
```

- NAT，网络地址转换。由于容器Ip是一个私有IP地址，8.8.8.8在收到容器的数据包后，想要回复，但是由于是私网地址无法路由。通过NAT协议，在容器数据包经过主机的eth0网卡发送到公网前，使用SNAT(Source Network Address Translation)将数据包的源ip改成eth0的网卡的ip，然后在主机收到回复的时候将ip改回来。
```shell
$ iptables -t nat -A POSTROUTING -s 192.175.0.1/24 -j MASQUERADE
```

此时容器ping host之外的ip地址，网络正常
```shell
$ nsenter -t 6064 -n ping -c 3 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=108 time=101 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=108 time=86.2 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=108 time=91.2 ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 86.206/92.830/101.080/6.180 ms
```
