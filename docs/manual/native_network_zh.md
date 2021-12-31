# native network使用指南

本文主要是指导iSulad社区开发者和使用者，如何使用native网络功能。

## 编译

目前native network的代码，使用了编译宏进行隔离，默认编译的iSulad已开启该功能。iSulad的依赖环境的安装请参考文档`docs/build_guide_zh.md`，此处不再赘述。下面仅对iSulad的编译进行说明。

```bash
$ cd iSulad
$ rm -rf build && mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```

## 网络插件

native网络需要安装cni二进制插件，开源仓库地址为`https://github.com/containernetworking/plugins`，经过测试建议安装`v0.9.0`及以上版本的cni插件，这里以文档发布时最新的v1.0.1版本为例。

```bash
$ wget https://github.com/containernetworking/plugins/releases/download/v1.0.1/cni-plugins-linux-amd64-v1.0.1.tgz
$ mkdir -p /opt/cni/bin/
$ tar -zxvf cni-plugins-linux-amd64-v1.0.1.tgz -C /opt/cni/bin/
```

## 启动iSulad

修改isulad daemon.json文件，配置cni。

```bash
$ vim /etc/isulad/daemon.json
	...
    "cni-bin-dir": "/opt/cni/bin",
    "cni-conf-dir": "/etc/cni/net.d",
    ...

# 启动isulad服务
$ isulad
```

`cni-bin-dir`为cni二进制文件的目录，不配置默认为`/opt/cni/bin`，`cni-conf-dir`为网络配置文件的目录，不配置默认为`/etc/cni/net.d`。若使用默认的目录，可不配置`daemon.json`文件，直接启动isulad。

## 使用native网络

native网络的使用与docker相似，下面展示一些简单的操作流程。

### 创建网络

```bash
$ isula network create cni0
cni0

$ isula network ls
NAME                 VERSION         PLUGIN
cni0                 0.4.0           bridge,portmap,firewall

$ isula network inspect cni0
[
    {
        "cniVersion": 0.4.0,
        "name": cni0,
        "plugins": [
            {
                "type": bridge,
                "bridge": isula-br0,
                "isGateway": true,
                "ipMasq": true,
                "hairpinMode": true,
                "ipam": {
                    "type": host-local,
                    "routes": [
                        {
                            "dst": 0.0.0.0/0
                        }
                    ],
                    "ranges": [
                        [
                            {
                                "subnet": 192.168.0.0/24,
                                "gateway": 192.168.0.1
                            }
                        ]
                    ]
                }
            },
            {
                "type": portmap,
                "capabilities": {
                    "portMappings": true
                }
            },
            {
                "type": firewall
            }
        ]
    }
]
```

### 容器生命周期操作

```bash
$ isula run -tid --net cni0 --name test busybox sh
3a933b6107114fe684393441ead8addc8994258dab4c982aedb1ea203f0df7d9

$ isula ps
CONTAINER ID    IMAGE   COMMAND CREATED         STATUS          PORTS   NAMES
3a933b610711    busybox "sh"    9 seconds ago   Up 9 seconds            test

$ isula inspect test
...
	"NetworkSettings": {
            "Bridge": "",
            "SandboxID": "",
            "LinkLocalIPv6Address": "",
            "LinkLocalIPv6PrefixLen": 0,
            "Ports": {},
            "CNIPorts": [],
            "SandboxKey": "/var/run/netns/isulacni-e93b9ac71757d204",
            "EndpointID": "",
            "Gateway": "",
            "GlobalIPv6Address": "",
            "GlobalIPv6PrefixLen": 0,
            "IPAddress": "",
            "IPPrefixLen": 0,
            "IPv6Gateway": "",
            "MacAddress": "",
            "Activation": true,
            "Networks": {
                "cni0": {
                    "Links": [],
                    "Alias": [],
                    "NetworkID": "",
                    "EndpointID": "",
                    "Gateway": "192.168.0.1",
                    "IPAddress": "192.168.0.4",
                    "IPPrefixLen": 24,
                    "IPv6Gateway": "",
                    "GlobalIPv6Address": "",
                    "GlobalIPv6PrefixLen": 0,
                    "MacAddress": "d2:74:53:c5:9c:be",
                    "IFName": "eth0",
                    "DriverOpts": {}
                }
            }
        }
...

$ ping 192.168.0.4
PING 192.168.0.4 (192.168.0.4) 56(84) bytes of data.
64 bytes from 192.168.0.4: icmp_seq=1 ttl=64 time=0.080 ms
64 bytes from 192.168.0.4: icmp_seq=2 ttl=64 time=0.038 ms
64 bytes from 192.168.0.4: icmp_seq=3 ttl=64 time=0.038 ms
^C
--- 192.168.0.4 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2084ms
rtt min/avg/max/mdev = 0.038/0.052/0.080/0.019 ms

$ isula rm -f test
3a933b6107114fe684393441ead8addc8994258dab4c982aedb1ea203f0df7d9
```

### 删除网络

```bash
$ isula network rm cni0
cni0

$ isula network ls
NAME                 VERSION         PLUGIN
```
