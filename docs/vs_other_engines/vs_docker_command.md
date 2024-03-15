# vs docker

**iSulad专注于单节点容器管理，因此docker swarm相关的功能由K8S支持！！！**

## 版本信息

| 名称   | 版本     |
| ------ | -------- |
| iSulad | 2.0.17   |
| docker | 20.10.17 |

## Server端配置对比

| Server配置项                       | docker                                                       | iSulad                                                       | 说明 |
| ---------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ---- |
| --add-runtime                      | yes，default []                                              | no                                                           |      |
| --allow-nondistributable-artifacts | yes                                                          | no                                                           |      |
| --api-cors-header                  | yes                                                          | no                                                           |      |
| --authorization-plugin             | yes                                                          | yes                                                          |      |
| --bip                              | yes                                                          | no                                                           |      |
| --bridge                           | yes                                                          | no                                                           |      |
| --cgroup-parent                    | yes                                                          | yes                                                          |      |
| --config-file                      | yes,default "/etc/docker/daemon.json"                        | no                                                           |      |
| --containerd                       | yes                                                          | no                                                           |      |
| --containerd-namespace             | yes,default "moby"                                           | no                                                           |      |
| --containerd-plugins-namespace     | yes,default "plugins.moby"                                   | no                                                           |      |
| --cpu-rt-period                    | yes                                                          | yes                                                           |      |
| --cpu-rt-runtime                   | yes                                                          | yes                                                           |      |
| --cri-containerd                   | yes                                                          | no                                                           |      |
| --cni-bin-dir                      | no                                                           | yes,Default: /opt/cni/bin                                    |      |
| --cni-conf-dir                     | no                                                           | yes,Default: /etc/cni/net.d                                  |      |
| --container-log-driver             | no                                                           | yes                                                          |      |
| --container-log-opts               | no                                                           | yes                                                          |      |
| --data-root                        | yes,default "/var/lib/docker"                                | no                                                           |      |
| --debug                            | yes                                                          | no                                                           |      |
| --default-address-pool             | yes                                                          | no                                                           |      |
| --default-cgroupns-mode            | yes                                                          | no                                                           |      |
| --default-gateway                  | yes                                                          | no                                                           |      |
| --default-gateway-v6               | yes                                                          | no                                                           |      |
| --default-ipc-mode                 | yes,default "private"                                        | no                                                           |      |
| --default-runtime                  | yes,default "runc"                                           | yes, default "lcr"               |      |
| --default-shm-size                 | yes,default 64MiB                                            | no                                                           |      |
| --default-ulimit                   | yes,default []                                               | default []                                                   |      |
| --dns/--dns-opt/--dns-search       | yes                                                          | no                                                           |      |
| --exec-opt                         | yes                                                          | no                                                           |      |
| --exec-root                        | yes,default "/var/run/docker"                                | no                                                           |      |
| --experimental                     | yes                                                          | no                                                           |      |
| --engine                           | no                                                           | yes                                                          |      |
| --fixed-cidr                       | yes                                                          | no                                                           |      |
| --fixed-cidr-v6                    | yes                                                          | no                                                           |      |
| --group                            | yes,default "docker"                                         | yes,default is isula                                         |      |
| --graph                            | no                                                           | yes                                                          |      |
| --help                             | yes                                                          | yes                                                          |      |
| --host                             | yes                                                          | yes                                                          |      |
| --hook-spec                        | no                                                           | yes                                                          |      |
| --host-gateway-ip                  | yes                                                          | no                                                           |      |
| --icc                              | yes,default true                                             | no                                                           |      |
| --init                             | yes                                                          | no                                                           |      |
| --init-path                        | yes                                                          | no                                                           |      |
| --image-layer-check                | no                                                           | yes                                                          |      |
| --insecure-registry                | yes                                                          | yes                                                          |      |
| --insecure-skip-verify-enforce     | no                                                           | yes,default false                                            |      |
| --ip/--ip-forward/--ip-masq        | yes,default 0.0.0.0/true/ture                                | no                                                           |      |
| --ip6tables                        | yes                                                          | no                                                           |      |
| --iptables                         | yes,default true                                             | no                                                           |      |
| --ipv6                             | yes                                                          | no                                                           |      |
| --label                            | yes                                                          | no                                                           |      |
| --live-restore                     | yes                                                          | no                                                           |      |
| --log-driver                       | yes,default "json-file"                                      | yes                                                          |      |
| --log-level                        | yes,the levels can be “debug”、“info"、"warn"、"error"、"fatal",default "info" | yes,set log level, the levels can be: FATAL ALERT CRIT ERROR WARN NO       TICE INFO DEBUG TRACE |      |
| --log-opt                          | yes,default map[]                                            | yes                                                          |      |
| --max-concurrent-downloads         | yes,default 3                                                | no                                                           |      |
| --max-concurrent-uploads           | yes,default 5                                                | no                                                           |      |
| --max-download-attempts            | yes,default 5                                                | no                                                           |      |
| --metrics-addr                     | yes                                                          | no                                                           |      |
| --mtu                              | yes                                                          | no                                                           |      |
| --network-control-plane-mtu        | yes,default 1500                                             | no                                                           |      |
| --no-new-privileges                | yes                                                          | no                                                           |      |
| --node-generic-resource            | yes                                                          | no                                                           |      |
| --native.umask                     | no                                                           | yes                                                          |      |
| --network-plugin                   | no                                                           | yes,default is null, suppport null and cni                   |      |
| --oom-score-adjust                 | yes                                                          | no                                                           |      |
| --pidfile                          | yes,default "/var/run/docker.pid"                            | yes                                                          |      |
| --pod-sandbox-image                | no                                                           | yes,default "pause-${machine}:3.0"                           |      |
| --raw-logs                         | yes                                                          | no                                                           |      |
| --registry-mirror                  | yes                                                          | yes                                                          |      |
| --rootless                         | yes                                                          | no                                                           |      |
| --seccomp-profile                  | yes                                                          | no                                                           |      |
| --selinux-enabled                  | yes                                                          | yes                                                          |      |
| --shutdown-timeout                 | yes,default 15                                               | no                                                           |      |
| --state                            | no                                                           | yes                                                          |      |
| --storage-driver                   | yes                                                          | yes,default overlay2                                         |      |
| --storage-opt                      | yes                                                          | yes                                                          |      |
| --swarm-default-advertise-addr     | yes                                                          | no                                                           |      |
| --start-timeout                    | no                                                           | yes                                                          |      |
| --tls/                             | yes                                                          | yes                                                          |      |
| --tlscacert                        | yes,default "/root/.docker/ca.pem"                           | yes,default "/root/.iSulad/ca.pem"                           |      |
| --tlscert                          | yes,default "/root/.docker/cert.pem"                         | yes,default "/root/.iSulad/cert.pem"                         |      |
| --tlskey                           | yes,default "/root/.docker/key.pem"                          | yes,default "/root/.iSulad/key.pem"                          |      |
| --tlsverify                        | yes                                                          | yes                                                          |      |
| --userland-proxy                   | yes,default true                                             | no                                                           |      |
| --userland-proxy-path              | yes,                                                         | no                                                           |      |
| --use-decrypted-key                | no                                                           | yes,default true                                             |      |
| --userns-remap                     | yes                                                          | yes                                                          |      |
| --version                          | yes                                                          | yes                                                          |      |
| --websocket-server-listening-port  | no                                                           | yes,default 10350                                            |      |

### 引擎安装及目录结构

```
Installing:
 iSulad                 
Installing dependencies:
 abseil-cpp                  
 clibcni                     
 grpc                   
 lcr                        
 lib-shim-v2  
 libwebsockets 
 lxc                         
 lxc-libs                
 protobuf                       
 protobuf-compiler
 re2       
```

说明：

- 推荐使用yum安装iSulad
- docker安装依赖containerd及runc

```
[root@openEuler home]# tree -L 2 /var/lib/isulad
/var/lib/isulad
├── engines
│   └── lcr
├── isulad_tmpdir
├── mnt
│   └── rootfs
├── storage
│   ├── NEED_CHECK
│   ├── overlay
│   ├── overlay-containers
│   ├── overlay-images
│   └── overlay-layers
└── volumes
    ├── 1ae268f386a1ead5114718a43756cbbf67f4f09899c0af5e994282842f981f4d
    └── d2e98da6546a19c861b8593a1362a316bcc4f5c248b016dd8a7a18166f016e7d
```

```
[root@openEuler home]# tree -L 1 /var/lib/docker
/var/lib/docker
├── builder
├── buildkit
├── containerd
├── containers
├── hooks
├── image
├── network
├── overlay2
├── plugins
├── runtimes
├── swarm
├── tmp
├── trust
└── volumes
```

## Client端子命令对比

### Usage：

```
isuld：	
	isula <command> [args...] 
docker：
	docker [OPTIONS] COMMAND
```

### Options对比

| Options     | docker                               | isula                                | 说明 |
| ----------- | ------------------------------------ | ------------------------------------ | ---- |
| --config    | yes,default "/root/.docker"          | no                                   |      |
| --context   | yes                                  | no                                   |      |
| --debug     | yes                                  | no                                   |      |
| --help      | yes                                  | yes                                  |      |
| --host      | yes                                  | yes                                  |      |
| --log-level | yes,default "info"                   | no                                   |      |
| --tls       | yes                                  | yes                                  |      |
| --tlscacert | yes,default "/root/.docker/ca.pem"   | yes,default "/root/.iSulad/ca.pem"   |      |
| --tlscert   | yes,default "/root/.docker/cert.pem" | yes,default "/root/.iSulad/cert.pem" |      |
| --tlskey    | yes,default "/root/.docker/key.pem"  | yes,default "/root/.iSulad/key.pem"  |      |
| --tlsverify | yes                                  | yes                                  |      |
| --version   | yes                                  | yes                                  |      |

### Management Commands对比

| Management Commands | docker | isula | 说明                                                         |
| ------------------- | ------ | ----- | ------------------------------------------------------------ |
| builder             | yes    | no    | 由isula-build支持镜像构建功能                                |
| config              | yes    | no    |                                                              |
| container           | yes    | no    |                                                              |
| context             | yes    | no    |                                                              |
| image               | yes    | no    |                                                              |
| manifest            | yes    | no    |                                                              |
| network             | yes    | no    |                                                              |
| node                | yes    | no    |                                                              |
| plugin              | yes    | no    |                                                              |
| secret              | yes    | no    |                                                              |
| service             | yes    | no    |                                                              |
| stack               | yes    | no    |                                                              |
| swarm               | yes    | no    | iSulad专注于单节点容器管理，因此docker swarm相关的功能由K8S支持 |
| system              | yes    | no    |                                                              |
| trust               | yes    | no    |                                                              |
| volume              | yes    | yes   |                                                              |

### Commands对比

| Commands | docker | isula         |
| -------- | ------ | ------------- |
| attach   | yes    | yes           |
| build    | yes    | no            |
| commit   | yes    | no            |
| cp       | yes    | yes           |
| create   | yes    | yes           |
| diff     | yes    | no            |
| events   | yes    | yes           |
| exec     | yes    | yes           |
| export   | yes    | yes           |
| history  | yes    | no            |
| images   | yes    | yes           |
| import   | yes    | yes//不支持流 |
| info     | yes    | yes           |
| inspect  | yes    | yes           |
| kill     | yes    | yes           |
| load     | yes    | yes           |
| login    | yes    | yes           |
| logout   | yes    | yes           |
| logs     | yes    | yes           |
| pause    | yes    | yes           |
| port     | yes    | no            |
| ps       | yes    | yes           |
| pull     | yes    | yes           |
| push     | yes    | no            |
| rename   | yes    | yes           |
| restart  | yes    | yes           |
| rm       | yes    | yes           |
| rmi      | yes    | yes           |
| run      | yes    | yes           |
| save     | yes    | no            |
| search   | yes    | no            |
| start    | yes    | yes           |
| stats    | yes    | yes           |
| stop     | yes    | yes           |
| tag      | yes    | yes           |
| top      | yes    | yes           |
| unpause  | yes    | yes           |
| update   | yes    | yes           |
| version  | yes    | yes           |
| wait     | yes    | yes           |

**说明：** 由isula-build支持镜像相关操作，包括build\push\save等

### volume相关

| volume Commands | docker | isula |
| --------------- | ------ | ----- |
| create          | yes    | no    |
| inspect         | yes    | no    |
| ls              | yes    | yes   |
| prune           | yes    | yes   |
| rm              | yes    | yes   |

**说明：** 当前iSulad的volume功能是用于匿名数据卷的管理，用于管理镜像中设置的数据卷；对于普通数据卷暂时未支持。主要基于优先级考虑：

- 命令行场景，可以通过`-v` 替代；
- K8S云场景，数据卷都是由K8S创建然后通过`-v`使用；



### 容器具体操作命令对比

#### attach  

```
Usage:  isula/docker attach [OPTIONS] CONTAINER
```

| OPTIONS                                  | docker | isula | 说明   |
| ---------------------------------------- | ------ | ----- | ------ |
| -D, --debug                              | no     | yes   |        |
| -H, --host                               | no     | yes   |        |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |        |
| --detach-keys                            | yes    | no    | 待补充 |
| --no-stdin                               | yes    | no    | 待补充 |
| --sig-proxy                              | yes    | no    | 待补充 |

#### cp

```
Usage:  isula/docker cp [OPTIONS] CONTAINER:SRC_PATH DEST_PATH|-
        isula/docker cp [OPTIONS] SRC_PATH|- CONTAINER:DEST_PATH
```

| OPTIONS                                  | docker | isula | 说明   |
| ---------------------------------------- | ------ | ----- | ------ |
| -D, --debug                              | no     | yes   |        |
| -H, --host                               | no     | yes   |        |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |        |
| -a, --archive                            | yes    | no    | 待补充 |
| -L, --follow-link                        | yes    | no    | 待补充 |

#### create

```
[root@openEuler ~]# isula create --help
Usage:  isula create [OPTIONS] --external-rootfs=PATH|IMAGE [COMMAND] [ARG...]

[root@openEuler ~]# docker create --help
Usage:  docker create [OPTIONS] IMAGE [COMMAND] [ARG...]
```

| OPTIONS               | docker | isula                   | 说明                              |
| --------------------- | ------ | ----------------------- | --------------------------------- |
| add-host              | yes    | yes                     |                                   |
| attach                | yes    | no                      | 不需要                            |
| annotation            | no     | yes                     |                                   |
| blkio-weight          | yes    | yes                     |                                   |
| blkio-weight-device   | yes    | yes                     |                                   |
| cap-add               | yes    | yes                     |                                   |
| cap-drop              | yes    | yes                     |                                   |
| cgroup-parent         | yes    | yes                     |                                   |
| cgroupns              | yes    | no                      | 主线已支持，待回合                |
| cidfile               | yes    | no                      | 会输出到stdout，没必要存入文件    |
| cpu-period            | yes    | yes                     |                                   |
| cpu-quota             | yes    | yes                     |                                   |
| cpu-rt-period         | yes    | yes                     |                                   |
| cpu-rt-runtime        | yes    | yes                     |                                   |
| cpu-shares            | yes    | yes                     |                                   |
| cpus                  | yes    | yes                     |                                   |
| cpuset-cpus           | yes    | yes                     |                                   |
| cpuset-mems           | yes    | yes                     |                                   |
| debug                 | no     | yes                     |                                   |
| device                | yes    | yes                     |                                   |
| device-cgroup-rule    | yes    | yes                     |                                   |
| device-read-bps       | yes    | yes                     |                                   |
| device-read-iops      | yes    | yes                     |                                   |
| device-write-bps      | yes    | yes                     |                                   |
| device-write-iops     | yes    | yes                     |                                   |
| disable-content-trust | yes    | no                      | 与pull相关，待支持                |
| dns                   | yes    | yes                     |                                   |
| dns-option            | yes    | yes，isula更名：dns-opt |                                   |
| dns-search            | yes    | yes                     |                                   |
| domainname            | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| entrypoint            | yes    | yes                     |                                   |
| env                   | yes    | yes                     |                                   |
| env-file              | yes    | yes                     |                                   |
| expose                | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| env-target-file       | no     | yes                     |                                   |
| external-rootfs       | no     | yes                     |                                   |
| files-limit           | no     | yes                     |                                   |
| gpus                  | yes    | no                      | 待支持                            |
| group-add             | yes    | yes                     |                                   |
| health-cmd            | yes    | yes                     |                                   |
| health-interval       | yes    | yes                     |                                   |
| health-retries        | yes    | yes                     |                                   |
| health-start-period   | yes    | yes                     |                                   |
| health-timeout        | yes    | yes                     |                                   |
| help                  | yes    | yes                     |                                   |
| hook-spec             | no     | yes                     |                                   |
| host                  | no     | yes                     |                                   |
| host-channel          | no     | yes                     |                                   |
| hostname              | yes    | yes                     |                                   |
| hugetlb-limit         | no     | yes                     |                                   |
| init                  | yes    | no                      |                                   |
| interactive           | yes    | yes                     |                                   |
| ip                    | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| ip6                   | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| ipc                   | yes    | yes                     |                                   |
| isolation             | yes    | no                      | windows相关，不支持               |
| kernel-memory         | yes    | yes                     |                                   |
| label                 | yes    | yes                     |                                   |
| label-file            | yes    | yes                     |                                   |
| link                  | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| link-local-ip         | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| log-driver            | yes    | yes                     |                                   |
| log-opt               | yes    | yes                     |                                   |
| mac-address           | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| memory                | yes    | yes                     |                                   |
| memory-reservation    | yes    | yes                     |                                   |
| memory-swap           | yes    | yes                     |                                   |
| memory-swappiness     | yes    | yes                     |                                   |
| mount                 | yes    | yes                     |                                   |
| name                  | yes    | yes                     |                                   |
| network               | yes    | yes，isula 更名：net    |                                   |
| network-alias         | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| no-healthcheck        | yes    | yes                     |                                   |
| ns-change-opt         | no     | yes                     |                                   |
| oom-kill-disable      | yes    | yes                     |                                   |
| oom-score-adj         | yes    | yes                     |                                   |
| pid                   | yes    | yes                     |                                   |
| pids-limit            | yes    | yes                     |                                   |
| platform              | yes    | no                      | 多平台支持，暂不需要              |
| privileged            | yes    | yes                     |                                   |
| publish               | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| publish-all           | yes    | no                      | 桥网络相关，暂不涉及，2.1版本支持 |
| pull                  | yes    | yes                     |                                   |
| read-only             | yes    | yes                     |                                   |
| restart               | yes    | yes                     |                                   |
| rm                    | yes    | no                      | bug，待补齐                       |
| runtime               | yes    | yes                     |                                   |
| security-opt          | yes    | yes                     |                                   |
| shm-size              | yes    | yes                     |                                   |
| stop-signal           | yes    | yes                     |                                   |
| stop-timeout          | yes    | no                      | 待补齐                            |
| storage-opt           | yes    | yes                     |                                   |
| sysctl                | yes    | yes                     |                                   |
| system-container      | no     | yes                     |                                   |
| tls                   | no     | yes                     |                                   |
| tlscacert             | no     | yes                     |                                   |
| tlscert               | no     | yes                     |                                   |
| tlskey                | no     | yes                     |                                   |
| tlsverify             | no     | yes                     |                                   |
| tmpfs                 | yes    | yes                     |                                   |
| tty                   | yes    | yes                     |                                   |
| ulimit                | yes    | yes                     |                                   |
| user                  | yes    | yes                     |                                   |
| userns                | yes    | no                      | 待补齐                            |
| user-remap            | no     | yes                     |                                   |
| uts                   | yes    | yes                     |                                   |
| volume                | yes    | yes                     |                                   |
| volume-driver         | yes    | no                      | volume拓展，暂不支持              |
| volumes-from          | yes    | yes                     |                                   |
| workdir               | yes    | yes                     |                                   |

#### events

```
Usage:  isula/docker events [OPTIONS]
```

| OPTIONS                                  | docker | isula | 说明                                |
| ---------------------------------------- | ------ | ----- | ----------------------------------- |
| -D, --debug                              | no     | yes   |                                     |
| -H, --host                               | no     | yes   |                                     |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                                     |
| -n, --name                               | yes    | yes   |                                     |
| -S, --since                              | yes    | yes   |                                     |
| -U, --until                              | yes    | yes   |                                     |
| -f, --filter                             | yes    | no    | C语言json解析限制，待部分支持       |
| --format                                 | yes    | no    | 显示优化，使用go template，无法支持 |

#### exec

```
Usage:  isula/docker exec [OPTIONS] CONTAINER COMMAND [ARG...]
```

| OPTIONS                                  | docker | isula | 说明                                                         |
| ---------------------------------------- | ------ | ----- | ------------------------------------------------------------ |
| -D, --debug                              | no     | yes   |                                                              |
| -H, --host                               | no     | yes   |                                                              |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                                                              |
| --detach                                 | yes    | yes   |                                                              |
| --detach-keys                            | yes    | no    | 待补齐                                                       |
| --env                                    | yes    | yes   |                                                              |
| --env-file                               | yes    | no    | 待补齐                                                       |
| --interactive                            | yes    | yes   |                                                              |
| --privileged                             | yes    | no    | exec提权为特权容器为高危险操作，不支持，可以通过特权容器代替 |
| --tty                                    | yes    | yes   |                                                              |
| --user                                   | yes    | yes   |                                                              |
| --workdir                                | yes    | yes   |                                                              |

#### export

```
[root@openEuler ~]# isula export --help
Usage:  isula export [command options] [ID|NAME]

[root@openEuler ~]# docker export --help
Usage:  docker export [OPTIONS] CONTAINER
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |
| --output                                 | yes    | yes   |

#### images

```
[root@openEuler ~]# isula images --help
Usage:  isula images

[root@openEuler ~]# docker images --help
Usage:  docker images [OPTIONS] [REPOSITORY[:TAG]]
```

| OPTIONS                                  | docker | isula | 说明                          |
| ---------------------------------------- | ------ | ----- | ----------------------------- |
| -D, --debug                              | no     | yes   |                               |
| -H, --host                               | no     | yes   |                               |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                               |
| --quiet                                  | yes    | yes   |                               |
| --filter                                 | yes    | yes   |                               |
| --all                                    | yes    | yes   |                               |
| --digests                                | yes    | no    | 待支持                        |
| --format                                 | yes    | no    | C语言json解析限制，待部分支持 |
| --no-trunc                               | yes    | no    | 待支持                        |

#### import

```
[root@openEuler ~]# isula import --help
Usage:  isula import file REPOSITORY[:TAG]

[root@openEuler ~]# docker import --help
Usage:  docker import [OPTIONS] file|URL|- [REPOSITORY[:TAG]]
```

| OPTIONS                                  | docker | isula | 说明              |
| ---------------------------------------- | ------ | ----- | ----------------- |
| -D, --debug                              | no     | yes   |                   |
| -H, --host                               | no     | yes   |                   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                   |
| --change                                 | yes    | no    | build能力，不支持 |
| --message                                | yes    | no    | 待支持            |
| --platform                               | yes    | no    | 多平台，暂不支持  |

#### info

```
[root@openEuler ~]# isula info --help
Usage:  isula info

[root@openEuler ~]# docker info --help
Usage:  docker info [OPTIONS]
```

| OPTIONS                                  | docker | isula | 说明                          |
| ---------------------------------------- | ------ | ----- | ----------------------------- |
| -D, --debug                              | no     | yes   |                               |
| -H, --host                               | no     | yes   |                               |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                               |
| --format                                 | yes    | no    | C语言json解析限制，待部分支持 |

#### inspect

```
[root@openEuler ~]# isula inspect --help
Usage:  isula inspect [options] CONTAINER|IMAGE [CONTAINER|IMAGE...]

[root@openEuler ~]# docker inspect --help
Usage:  docker inspect [OPTIONS] NAME|ID [NAME|ID...]
```

| OPTIONS                                  | docker | isula | 说明                           |
| ---------------------------------------- | ------ | ----- | ------------------------------ |
| -D, --debug                              | no     | yes   |                                |
| -H, --host                               | no     | yes   |                                |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                                |
| --format                                 | yes    | yes   |                                |
| --size                                   | yes    | no    | 待补充                         |
| --type                                   | yes    | no    | iSulad自动识别类型，不需要指定 |
| --time                                   | no     | yes   |                                |

#### kill

```
Usage:  isula/docker kill [OPTIONS] CONTAINER [CONTAINER...]
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |
| --signal                                 | yes    | yes   |

#### load

```
[root@openEuler ~]# isula load --help
Usage:  isula load [OPTIONS] --input=FILE

[root@openEuler ~]# docker load --help
Usage:  docker load [OPTIONS]
```

| OPTIONS                                  | docker | isula | 说明                                    |
| ---------------------------------------- | ------ | ----- | --------------------------------------- |
| -D, --debug                              | no     | yes   |                                         |
| -H, --host                               | no     | yes   |                                         |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                                         |
| --input                                  | yes    | yes   |                                         |
| --quiet                                  | yes    | no    | isulad不支持进度条，默认为quiet，待优化 |
| --tag                                    | no     | yes   |                                         |

#### login

```
Usage:  isula/docker login [OPTIONS] SERVER
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |
| --password                               | yes    | yes   |
| --password-stdin                         | yes    | yes   |
| --username                               | yes    | yes   |

#### logout

```
Usage:  isula/docker logout [SERVER]
```

| PTIONS                                   | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |

#### logs

```
Usage:  isula/docker logs [OPTIONS] CONTAINER
```

| OPTIONS                                  | docker | isula | 说明                           |
| ---------------------------------------- | ------ | ----- | ------------------------------ |
| -D, --debug                              | no     | yes   |                                |
| -H, --host                               | no     | yes   |                                |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                                |
| --details                                | yes    | no    | isulad日志驱动简洁，不考虑支持 |
| --follow                                 | yes    | yes   |                                |
| --since                                  | yes    | no    | 待支持                         |
| --tail                                   | yes    | yes   |                                |
| --timestamps                             | yes    | yes   |                                |
| --until                                  | yes    | no    | 待支持                         |

#### pause/unpause

```
Usage:  isula pause [OPTIONS] CONTAINER [CONTAINER...]
Usage:  isula unpause [OPTIONS] CONTAINER [CONTAINER...]
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |

#### ps

```
Usage:  isula/docker ps [OPTIONS]
```

| OPTIONS                                  | docker | isula | 说明             |
| ---------------------------------------- | ------ | ----- | ---------------- |
| -D, --debug                              | no     | yes   |                  |
| -H, --host                               | no     | yes   |                  |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                  |
| --all                                    | yes    | yes   |                  |
| --filter                                 | yes    | yes   |                  |
| --format                                 | yes    | yes   |                  |
| --last                                   | yes    | no    | 主线支持，待回合 |
| --latest                                 | yes    | no    | 主线支持，待回合 |
| --no-trunc                               | yes    | yes   |                  |
| --quiet                                  | yes    | yes   |                  |
| --size                                   | yes    | no    | 待支持           |

#### pull

| OPTIONS                                  | docker | isula | 说明                       |
| ---------------------------------------- | ------ | ----- | -------------------------- |
| -D, --debug                              | no     | yes   |                            |
| -H, --host                               | no     | yes   |                            |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                            |
| --all-tags                               | yes    | no    | 待支持                     |
| --disable-content-trust                  | yes    | no    | 待支持                     |
| --platform                               | yes    | no    | 待支持，优先级较低         |
| --quiet                                  | yes    | no    | isulad不支持进度条，待优化 |

#### rename

```
[root@openEuler ~]# isula rename --help
Usage:  isula rename [OPTIONS] OLD_NAME NEW_NAME

[root@openEuler ~]# docker rename --help
Usage:  docker rename CONTAINER NEW_NAME
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |

#### restart

```
Usage:  docker/isula restart [OPTIONS] CONTAINER [CONTAINER...]
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |
| --time                                   | yes    | yes   |

#### rm

```
Usage:  isula/docker rm [OPTIONS] CONTAINER [CONTAINER...]
```

| OPTIONS                                  | docker | isula | 说明                              |
| ---------------------------------------- | ------ | ----- | --------------------------------- |
| -D, --debug                              | no     | yes   |                                   |
| -H, --host                               | no     | yes   |                                   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                                   |
| --force                                  | yes    | yes   |                                   |
| --volumes                                | yes    | yes   |                                   |
| --link                                   | yes    | no    | 桥网络相关，暂不涉及，2.1版本支持 |

#### rmi

```
Usage:  isula/docker rmi [OPTIONS] IMAGE [IMAGE...]
```

| OPTIONS                                  | docker | isula | 说明                   |
| ---------------------------------------- | ------ | ----- | ---------------------- |
| -D, --debug                              | no     | yes   |                        |
| -H, --host                               | no     | yes   |                        |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                        |
| --force                                  | yes    | yes   |                        |
| --no-prune                               | yes    | no    | 场景较少，暂不建议支持 |

#### run

run命令与create基本一致，只在Run container in background相关功能有所区别，增量对比run接口：

```
[root@openEuler ~]# isula run --help
Usage:  isula run [OPTIONS] ROOTFS|IMAGE [COMMAND] [ARG...]

[root@openEuler ~]# docker run --help
Usage:  docker run [OPTIONS] IMAGE [COMMAND] [ARG...]
```

| OPTIONS       | docker | isula | 说明   |
| ------------- | ------ | ----- | ------ |
| --detach      | yes    | yes   |        |
| --detach-keys | yes    | no    | 待支持 |

#### start

```
Usage:  isula/docker start [OPTIONS] CONTAINER [CONTAINER...]
```

| OPTIONS                                  | docker | isula | 说明   |
| ---------------------------------------- | ------ | ----- | ------ |
| -D, --debug                              | no     | yes   |        |
| -H, --host                               | no     | yes   |        |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |        |
| --attach                                 | yes    | yes   |        |
| --detach-keys                            | yes    | no    | 待支持 |
| --interactive                            | yes    | no    | 待支持 |

#### stats

```
Usage:  isula stats [OPTIONS] [CONTAINER...]
```

| OPTIONS                                  | docker | isula | 说明                          |
| ---------------------------------------- | ------ | ----- | ----------------------------- |
| -D, --debug                              | no     | yes   |                               |
| -H, --host                               | no     | yes   |                               |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                               |
| --all                                    | yes    | yes   |                               |
| --format                                 | yes    | no    | C语言json解析限制，待部分支持 |
| --no-stream                              | yes    | yes   |                               |
| --original                               | no     | yes   |                               |

#### stop

```
Usage:  isula stop [OPTIONS] CONTAINER [CONTAINER...]
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |
| --force                                  | no     | yes   |
| --time                                   | yes    | yes   |

#### tag

```
Usage:  isula/docker tag SOURCE_IMAGE[:TAG] TARGET_IMAGE[:TAG]
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |

#### top

```
Usage:  isula/docker top [OPTIONS] CONTAINER [ps OPTIONS]
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |

#### update

```
Usage:  isula/docker update [OPTIONS] CONTAINER [CONTAINER...]
```

| OPTIONS                                  | docker | isula | 说明   |
| ---------------------------------------- | ------ | ----- | ------ |
| -D, --debug                              | no     | yes   |        |
| -H, --host                               | no     | yes   |        |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |        |
| blkio-weight                             | yes    | yes   |        |
| cpu-period                               | yes    | yes   |        |
| cpu-quota                                | yes    | yes   |        |
| cpu-rt-period                            | yes    | yes   |        |
| cpu-rt-runtime                           | yes    | yes   |        |
| cpu-shares                               | yes    | yes   |        |
| cpus                                     | yes    | yes   |        |
| cpuset-cpus                              | yes    | yes   |        |
| cpuset-mems                              | yes    | yes   |        |
| kernel-memory                            | yes    | yes   |        |
| memory                                   | yes    | yes   |        |
| memory-reservation                       | yes    | yes   |        |
| memory-swap                              | yes    | yes   |        |
| pids-limit                               | yes    | no    | 待补充 |
| restart                                  | yes    | yes   |        |

#### version

```
Usage:  isula/docker version [OPTIONS]
```

| OPTIONS                                  | docker | isula | 说明                          |
| ---------------------------------------- | ------ | ----- | ----------------------------- |
| -D, --debug                              | no     | yes   |                               |
| -H, --host                               | no     | yes   |                               |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |                               |
| --format                                 | yes    | no    | C语言json解析限制，待部分支持 |
| --kubeconfig                             | yes    | no    | 不涉及                        |

#### wait

```
[root@openEuler ~]# isula wait --help
Usage:  isula wait [OPTIONS] CONTAINER [CONTAINER...]

[root@openEuler ~]# docker wait --help
Usage:  docker wait CONTAINER [CONTAINER...]
```

| OPTIONS                                  | docker | isula |
| ---------------------------------------- | ------ | ----- |
| -D, --debug                              | no     | yes   |
| -H, --host                               | no     | yes   |
| --tls/tlscacert/tlscert/tlskey/tlsverify | no     | yes   |



## 容器内环境差异对比

说明：所有的对比均使用相同的镜像，并在同一宿主机下执行，对比测试使用openeuler提供的容器基础镜像，通过load导入镜像并使用

### 容器内环境变量对比

```
[root@openEuler ~]# isula exec -it isula_test bash


Welcome to 5.10.0-60.48.0.76.oe2203.x86_64

System information as of time:  Tue Sep  6 15:19:22 CST 2022

System load:    0.04
Processes:      6
Memory used:    9.8%
Swap used:      .1%
Usage On:       9%
Users online:   0

[root@localhost /]# env
PWD=/
container=lxc
HOME=/root
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
TERM=xterm
SHLVL=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
```

```
[root@openEuler ~]# docker exec -it docker_test bash                              

Welcome to 5.10.0-60.48.0.76.oe2203.x86_64

System information as of time:  Tue Sep  6 15:19:38 CST 2022

System load:    0.03
Processes:      6
Memory used:    10.4%
Swap used:      .1%
Usage On:       9%
Users online:   0

[root@dba7c203a713 /]# env
HOSTNAME=dba7c203a713
PWD=/
HOME=/root
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
TERM=xterm
SHLVL=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
[root@dba7c203a713 /]#
```

说明：

- 差异主要体现在HOSTNAME不一致以及isula容器内新增container环境变量
- **https://gitee.com/openeuler/iSulad/issues/I5PY6W?from=project-issue**

### 容器内内核参数对比

```
[root@openEuler ~]# isula exec -it isula_test bash


Welcome to 5.10.0-60.48.0.76.oe2203.x86_64

System information as of time:  Tue Sep  6 15:19:22 CST 2022

System load:    0.04
Processes:      6
Memory used:    9.8%
Swap used:      .1%
Usage On:       9%
Users online:   0


[root@localhost /]# sysctl -a
abi.vsyscall32 = 1
crypto.fips_enabled = 0
debug.exception-trace = 1
debug.kprobes-optimization = 1
...
```

对比docker及isula容器内sysctl执行结果：

| 内核参数                              | docker         | isula                   | 说明                         |
| ------------------------------------- | -------------- | ----------------------- | ---------------------------- |
| kernel.hostname                       | 容器id         | localhost               |                              |
| kernel.random.entropy_avail//随机熵值 | 与host保持一致 | 比host少1               | ？？？                       |
| net.ipv4.conf.eth0*                   | 容器内支持网络 | 不存在相关配置          | iSula容器内部没有网络        |
| net.ipv4.neigh.eth0*                  | 容器内支持网络 | 不存在相关配置          | iSula容器内部没有网络        |
| net.ipv6.conf.eth0*                   | 容器内支持网络 | 不存在相关配置          | iSula容器内部没有网络        |
| net.ipv6.neigh.eth0*                  | 容器内支持网络 | 不存在相关配置          | iSula容器内部没有网络        |
| net.ipv4.ip_unprivileged_port_start   | 0              | 与host保持一致（1024）  | 容器内部没有网络，继承OS信息 |
| net.ipv4.ping_group_range             | 0 2147483647   | 与host保持一致（1   0） | 容器内部没有网络，继承OS信息 |
| net.ipv6.conf.all.disable_ipv6        | 1              | 与host保持一致（0）     | 容器内部没有网络，继承OS信息 |
| net.ipv6.conf.default.disable_ipv6    | 1              | 与host保持一致（0）     | 容器内部没有网络，继承OS信息 |
| net.ipv6.conf.lo.disable_ipv6         | 1              | 与host保持一致（0）     | 容器内部没有网络，继承OS信息 |

说明：isula容器支持CNI网络

## 容器外环境差异对比

### 容器端口映射

```
[root@openEuler home]# netstat | grep docker
unix  2      [ ]         STREAM     CONNECTED     700961   /var/run/docker.sock
unix  3      [ ]         STREAM     CONNECTED     102786   /var/run/docker/containerd/containerd.sock
unix  3      [ ]         STREAM     CONNECTED     104779   /var/run/docker/containerd/containerd.sock
unix  3      [ ]         STREAM     CONNECTED     104012   /var/run/docker/containerd/containerd.sock
[root@openEuler home]#
```

isula的通过netstat接口差不到，但是lsof又有不少，这个地方缺少一个好的呈现工具，求助！！！

### 容器守护进程对比

```
[root@openEuler ~]# isula ps -a
CONTAINER ID    IMAGE                   COMMAND CREATED                 STATUS              PORTS   NAMES
23d5ced49e2c    openeuler-22.03-lts     "bash"  About an hour ago       Up About an hour            isula_test
[root@openEuler ~]# ps -ef | grep 23d5ced49e2c | grep -v grep
root     1312260       1  0 15:19 ?        00:00:00 [lxc monitor] /var/lib/isulad/engines/lcr 23d5ced49e2c69c88f5a69f42419276fdbd29ddc57c4b0f5af4b2955db4f06ee
[root@openEuler ~]# ps ajxf  | grep isulad | grep -v grep
      1 1301105 1301105 1301105 ?             -1 Ssl      0   0:05 /usr/bin/isulad
      1 1312260 1312260 1312260 ?             -1 Ss       0   0:00 [lxc monitor] /var/lib/isulad/engines/lcr 23d5ced49e2c69c88f5a69f42419276fdbd29ddc57c4b0f5af4b2955db4f06ee
```

```
[root@openEuler home]# docker ps -a
CONTAINER ID   IMAGE                 COMMAND   CREATED       STATUS       PORTS     NAMES
dba7c203a713   openeuler-22.03-lts   "bash"    2 hours ago   Up 2 hours             docker_test
[root@openEuler home]# ps -ef | grep dba7c203a713 | grep -v grep
root     1311633       1  0 15:18 ?        00:00:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id dba7c203a713c7c6d28f45182581e0d117ef2c607e8b7efb036ea579a28ca449 -address /var/run/docker/containerd/containerd.sock
[root@openEuler ~]# ps ajxf  | grep docker | grep -v grep
      1   50367   50367   50367 ?             -1 Ssl      0   4:52 /usr/bin/dockerd --live-restore -D --insecure-registry rnd-dockerhub.huawei.com
  50367   50376   50376   50376 ?             -1 Ssl      0   4:31  \_ containerd --config /var/run/docker/containerd/containerd.toml --log-level debug
      1 1311633 1311633   50376 ?             -1 Sl       0   0:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id dba7c203a713c7c6d28f45182581e0d117ef2c607e8b7efb036ea579a28ca449 -address /var/run/docker/containerd/containerd.sock
```

说明：

- iSula引擎只需要isulad一个常驻进程，docker除了dockerd还需要containerd进程containerd-shim进程接管
- iSula容器启动后由lxc monitor进程接管，docker容器启动后由containerd-shim接管

### 容器挂载点对比

```
[root@openEuler home]# isula ps -a
CONTAINER ID    IMAGE                   COMMAND CREATED         STATUS          PORTS   NAMES
23d5ced49e2c    openeuler-22.03-lts     "bash"  2 hours ago     Up 2 hours              isula_test
[root@openEuler home]# mount | grep isula
/dev/mapper/openeuler_openeuler-root on /var/lib/isulad/mnt type ext4 (rw,relatime,seclabel)
/dev/mapper/openeuler_openeuler-root on /var/lib/isulad/storage/overlay type ext4 (rw,relatime,seclabel)
shm on /var/lib/isulad/engines/lcr/23d5ced49e2c69c88f5a69f42419276fdbd29ddc57c4b0f5af4b2955db4f06ee/mounts/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,seclabel,size=65536k)
overlay on /var/lib/isulad/storage/overlay/23d5ced49e2c69c88f5a69f42419276fdbd29ddc57c4b0f5af4b2955db4f06ee/merged type overlay (rw,relatime,seclabel,lowerdir=/var/lib/isulad/storage/overlay/l/0b75d5b532ae51147239268901,upperdir=/var/lib/isulad/storage/overlay/23d5ced49e2c69c88f5a69f42419276fdbd29ddc57c4b0f5af4b2955db4f06ee/diff,workdir=/var/lib/isulad/storage/overlay/23d5ced49e2c69c88f5a69f42419276fdbd29ddc57c4b0f5af4b2955db4f06ee/work)
```

```
[root@openEuler home]# docker ps -a
CONTAINER ID   IMAGE                 COMMAND   CREATED         STATUS         PORTS     NAMES
15911ef52d59   openeuler-22.03-lts   "bash"    6 minutes ago   Up 6 minutes             docker_test

[root@openEuler home]# mount | grep docker
overlay on /var/lib/docker/overlay2/836bea2aefeecc19afc45ab4ba452aaade05ef714594fb12852c80e896aa71dd/merged type overlay (rw,relatime,seclabel,lowerdir=/var/lib/docker/overlay2/l/GHERFPZNJK4KRWPHBXJLPYYRJX:/var/lib/docker/overlay2/l/ZZJTTTJRGJJAHAQ3A3K3SAEFKV,upperdir=/var/lib/docker/overlay2/836bea2aefeecc19afc45ab4ba452aaade05ef714594fb12852c80e896aa71dd/diff,workdir=/var/lib/docker/overlay2/836bea2aefeecc19afc45ab4ba452aaade05ef714594fb12852c80e896aa71dd/work)
nsfs on /run/docker/netns/9e865094f37f type nsfs (rw)
```

说明：

- 均使用默认存储驱动overlay2
- isula容器挂载点包括：shm、overlay
- docker容器挂载点：overlay、nsfs
