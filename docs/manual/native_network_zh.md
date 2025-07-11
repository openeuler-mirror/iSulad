# native network使用指南

本文主要是指导iSulad社区开发者和使用者，如何使用native网络功能。

## 编译

目前native network的代码，仅存在在于iSulad和lcr的master分支进行迭代演进。在iSulad中使用了编译宏进行隔离，且默认编译已开启。iSulad依赖环境的安装请参考文档`docs/build_docs/guide/build_guide_zh.md`，此处不再赘述。下面仅对lcr和iSulad的编译进行说明。

```bash

# build and install lcr
$ git clone https://gitee.com/openeuler/lcr.git
$ cd lcr
# master分支
$ mkdir build
$ cd build
$ cmake ..
$ make -j $(nproc)
$ make install

# build and install iSulad
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
# master分支
$ mkdir build
$ cd build
# ENABLE_NATIVE_NETWORK默认开启
$ cmake -DENABLE_NATIVE_NETWORK=ON ..
$ make -j $(nproc)
$ make install
```

## 网络插件

native网络需要安装cni二进制插件，开源仓库地址为`https://github.com/containernetworking/plugins`，经过测试建议安装`v0.9.0`及以上版本的cni插件，这里以最新的v1.3.0版本为例。

```bash
$ wget https://github.com/containernetworking/plugins/releases/download/v1.3.0/cni-plugins-linux-amd64-v1.3.0.tgz
$ mkdir -p /opt/cni/bin/
$ tar -zxvf cni-plugins-linux-amd64-v1.3.0.tgz -C /opt/cni/bin/
```

## 版本说明

iSulad版本及其自身所支持的CNI规范和推荐的网络插件版本如下表所示：

iSulad version|CNI spec version|cni-plugins version
---|---|---
v2.1.3 and earlier|spec-v0.4.0|v0.9.1
v2.1.4|spec-v1.0.0|v1.3.0

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
cni0                 1.0.0           bridge,portmap,firewall

$ isula network inspect cni0
[
    {
        "cniVersion": 1.0.0,
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

## isula network create

### 描述

用于创建一个native网络，isulad会创建一个符合cni标准的网络配置文件，并存放在`cni-conf-dir`目录下

### 用法

```bash
isula network create [OPTIONS] [NETWORK]
```

### 参数

| 参数 | 说明 |
| - | - |
| -d, --driver | 网络驱动，默认值为bridge桥接模式，目前仅支持bridge模式 |
| --gateway | 子网的ipv4或者ipv6网关，指定gateway参数必须指定subnet参数，如果不指定gateway，则使用子网段中的第一个IP作为网关 |
| --internal | 使用该网络的容器，限制其与外部的网络交互 |
| --subnet | 符合CIDR格式的子网段 |

## isula network inspect

### 描述

用于查询一个或多个已经创建的native网络

### 用法

```bash
isula network inspect [OPTIONS] NETWORK [NETWORK...]
```

### 参数

| 参数 | 说明 |
| - | - |
| -f, --format | 使用模板格式化输出 |

## isula network ls

### 描述

用于列出所有已经创建的native网络

### 用法

```bash
isula network ls [OPTIONS]
```

### 参数

| 参数 | 说明 |
| - | - |
| -f, --filter | 指定筛选条件 |
| -q, --quiet | 仅输出网络名字 |

## isula network rm

### 描述

删除已经创建的一个或多个native网络，同时会删除对应的网桥设备，以及网络配置文件。

### 用法

```bash
isula network rm [OPTIONS] NETWORK [NETWORK...]
```

### 参数

无

## isula create/run

### 描述

添加了相对应的网络参数，在创建/启动容器时，为容器添加网络能力。

### 用法

```bash
isula run [OPTIONS] ROOTFS|IMAGE [COMMAND] [ARG...]
```

### 参数

仅展示与网络相关的参数

| 参数 | 说明 |
| - | - |
| --expose | 暴露容器端口 |
| --net, --network | 加入网络 |
| -p, --publish | 将主机端口映射到容器端口，格式为`<hostport>:<container port>`. --publish/-p需要指定--network/--net |
| -P, --publish-all | 将所有的exposed端口映射到主机上的随机端口 |

**注意：当使用 --network/--net 参数将容器加入 bridge 网络时，--publish/-p 参数才会生效并按指定的端口映射规则工作。在其他网络模式下，如 host 或 none 等，--publish/-p 参数将被忽略，无法实现预期的端口映射功能。**
