## Setup Bridge Network for Container

1. Create container
```shell
# create container by isula
$ isula run -tid busybox sh
2b6daf278a79b3de03c2674ca4fac3ae540339fe214db739dd5cfc1e73146fea
# get container's pid
$ isula inspect 2b6daf27 | grep -i pid
            "Pid": 6064,
            "PidMode": "",
            "PidsLimit": 0,
```

2. Create bridge
```shell
# create bridge device
$ ip link add my-bridge type bridge
# setup bridge device
$ ip link set my-bridge up
```

3. Create veth peer
```shell
# create veth peer devices, one on host, another in container
$ ip link add veth-host type veth peer name veth-container netns 6064
# setup veth peer devices
$ ip link set veth-host up
$ nsenter -t 6064 -n ip link set veth-container up
# add veth on host to bridge
$ ip link set dev veth-host master my-bridge
```

4. Set IP address, subnet 192.175.0.0/24
```shell
# set ip address for my-bridge, and add ip route for 192.175.0.0/24 on host
$ ip addr add 192.175.0.1/24 dev my-bridge
# set ip address for container
$ nsenter -t 6064 -n ip addr add 192.175.0.2/24 dev veth-container
# setip route for container
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

now container cannot ping ip address outside of host
```shell
$ nsenter -t 6064 -n ping -c 3 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2115ms
```

5. setup ip forward, network address translation
- IP forwad: The host has more than one network device, if one of them receives the data packets, it sends the packets to another network device according to the destination IP address of the data packets, and then send packets continues according to the routing table. This is usually what a router is supposed to do.
```shell
# setup forward on host
$ sysctl -w net.ipv4.ip_forward=1
# iptables filter table FORWARD Chian, default policy is drop. Add accept rule for my-bridge
$ iptables -A FORWARD -o my-bridge -j ACCEPT
$ iptables -A FORWARD -i my-bridge -j ACCEPT
```

- NAT: Network address translation. Since the container IP is a private IP address, 8.8.8.8 wants to reply after receiving the data packets of the container, but it cannot be routed because it is a private network address. Through the NAT protocol, before the container data packets is sent to the public network address through the host's eth0 network device, SNAT (Source Network Address Translation) is used to change the source ip of the data packets to the ip of the eth0 network device, and then when the host receives the reply, it will change the ip back.
```shell
$ iptables -t nat -A POSTROUTING -s 192.175.0.1/24 -j MASQUERADE
```

now container can ping ip address outside of host now
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
