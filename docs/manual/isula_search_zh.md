# isula search 指南
本文主要是指导iSulad社区开发者和使用者，如何使用isula search功能。
##   启动iSulad

修改isulad的daemon.json，配置registry-mirrors。

```sh
$ vim /etc/isulad/daemon.json
	...
  "registry-mirrors": [
        "docker.io"
    ],
    ...
```

**tips**：
1. 若使用isula search时不指定搜索的registry，则默认使用registry-mirrors中配置的registry。

2. 若想要使用http协议访问registry，则还需要将registry地址加入到insecure-registries配置中：

```sh
"insecure-registries": [
    ],
```

之后使用root权限启动isulad服务：

```sh
$ isulad
```

## 使用方法

###  描述

用于搜索镜像仓库中包含指定名称的镜像，并返回用户镜像的相关信息。

### 用法

```
isula search [OPTIONS] TERM
```

### 参数

| 参数        | 说明                                                         |
| ----------- | ------------------------------------------------------------ |
| --limit     | 搜索结果返回的最大镜像数量限制，默认值为25，设置的范围为[1,100] |
| --no-trunc  | 返回结果中镜像的描述是否截断，默认截断，设置该参数后不截断； |
| -f,--filter | 指定筛选条件；可使用的筛选条件有：is-automated、 is-official和stars |
| --format    | 指定输出的格式                                               |

## 使用示例

### 通过名字搜索镜像

搜索名称包含`busybox`的镜像:

```sh
$  isula search busybox

NAME                                 DESCRIPTION                                         STARS     OFFICIAL     AUTOMATED
busybox                              Busybox base image.                                 2791      [OK]
radial/busyboxplus                   Full-chain, Internet enabled, busybox made f...     49                     [OK]
yauritux/busybox-curl                Busybox with CURL                                   18
arm32v7/busybox                      Busybox base image.                                 10
odise/busybox-curl                   -                                                   4                      [OK]
arm64v8/busybox                      Busybox base image.                                 4
i386/busybox                         Busybox base image.                                 3
joeshaw/busybox-nonroot              Busybox container with non-root user nobody         2
p7ppc64/busybox                      Busybox base image for ppc64.                       2
busybox42/zimbra-docker-centos       A Zimbra Docker image, based in ZCS 8.8.9 an...     2                      [OK]
s390x/busybox                        Busybox base image.                                 2
prom/busybox                         Prometheus Busybox Docker base images               2                      [OK]
vukomir/busybox                      busybox and curl                                    1
amd64/busybox                        Busybox base image.                                 1
ppc64le/busybox                      Busybox base image.                                 1
spotify/busybox                      Spotify fork of https://hub.docker.com/_/bus...     1
busybox42/nginx_php-docker-centos    This is a nginx/php-fpm server running on Ce...     1                      [OK]
rancher/busybox                      -                                                   0
ibmcom/busybox                       -                                                   0
openebs/busybox-client               -                                                   0
antrea/busybox                       -                                                   0
ibmcom/busybox-amd64                 -                                                   0
ibmcom/busybox-ppc64le               -                                                   0
busybox42/alpine-pod                 -                                                   0
arm32v5/busybox                      Busybox base image.                                 0      
```

### 设置--no-trunc参数

```sh
$ isula search --filter=stars=3 --no-trunc busybox

NAME                        DESCRIPTION                                                                                STARS     OFFICIAL     AUTOMATED
busybox                     Busybox base image.                                                                        2791      [OK]
radial/busyboxplus          Full-chain, Internet enabled, busybox made from scratch. Comes in git and cURL flavors.    49                     [OK]
yauritux/busybox-curl       Busybox with CURL                                                                          18
arm32v7/busybox             Busybox base image.                                                                        10
odise/busybox-curl          -                                                                                          4                      [OK]
arm64v8/busybox             Busybox base image.                                                                        4
i386/busybox                Busybox base image.                                                                        3                   
```

### 设置limit参数

```sh
$isula search --limit=1 busybox 

NAME                            DESCRIPTION                                             STARS   OFFICIAL        AUTOMATED 
busybox                         Busybox base image.                                     2789    [OK]                      
```

### 设置Filter参数

一个Filter参数是一对key=value对，如果想要设置多个filter，则需要用多个--filter，例如： `--filter is-automated=true --filter stars=3`。

现有支持的filter如下：

- stars(int)：指定镜像最少的stars数量 
- is-automated (boolean - true or false) :指定镜像是否为 automated
- is-official (boolean - true or false) ：指定镜像是否为official

#### stars

```
$ isula search --filter stars=3 busybox

NAME                        DESCRIPTION                                         STARS     OFFICIAL     AUTOMATED
busybox                     Busybox base image.                                 2791      [OK]
radial/busyboxplus          Full-chain, Internet enabled, busybox made f...     49                     [OK]
yauritux/busybox-curl       Busybox with CURL                                   18
arm32v7/busybox             Busybox base image.                                 10
odise/busybox-curl          -                                                   4                      [OK]
arm64v8/busybox             Busybox base image.                                 4
i386/busybox                Busybox base image.                                 3
```

#### is-automated

```
$ isula search --filter is-automated=true busybox

NAME                                 DESCRIPTION                                         STARS     OFFICIAL     AUTOMATED
radial/busyboxplus                   Full-chain, Internet enabled, busybox made f...     49                     [OK]
odise/busybox-curl                   -                                                   4                      [OK]
busybox42/zimbra-docker-centos       A Zimbra Docker image, based in ZCS 8.8.9 an...     2                      [OK]
prom/busybox                         Prometheus Busybox Docker base images               2                      [OK]
busybox42/nginx_php-docker-centos    This is a nginx/php-fpm server running on Ce...     1                      [OK]
```

#### is-official

```
$ isula search --filter is-official=true --filter stars=3 busybox

NAME                        DESCRIPTION                                         STARS     OFFICIAL     AUTOMATED
busybox                     Busybox base image.                                 2791      [OK]
```

### 设置format参数

通过format参数可以指定搜索结果输出的形式。

| 占位符         | 描述                         |
| :------------- | :--------------------------- |
| `.Name`        | 镜像名称                     |
| `.Description` | 镜像描述                     |
| `.StarCount`   | 镜像的stars数量              |
| `.IsOfficial`   | 如果镜像是Official则显示OK   |
| `.IsAutomated` | 如果镜像是自动构建的则显示OK |

例如：

```
$ isula search --format "table {{.Name}}\t{{.IsAutomated}}\t{{.IsOfficial}}" nginx

NAME                                               AUTOMATED     OFFICIAL
nginx                                                            [OK]
linuxserver/nginx
bitnami/nginx                                      [OK]
ubuntu/nginx
bitnami/nginx-ingress-controller                   [OK]
rancher/nginx-ingress-controller
webdevops/nginx                                    [OK]
ibmcom/nginx-ingress-controller
bitnami/nginx-exporter
bitnami/nginx-ldap-auth-daemon
kasmweb/nginx
rancher/nginx-ingress-controller-defaultbackend
rancher/nginx
rapidfort/nginx
vmware/nginx
vmware/nginx-photon
wallarm/nginx-ingress-controller
bitnami/nginx-intel
ibmcom/nginx-ingress-controller-ppc64le
ibmcom/nginx-ppc64le
rapidfort/nginx-ib
rancher/nginx-conf
rancher/nginx-ssl
continuumio/nginx-ingress-ws
rancher/nginx-ingress-controller-amd64
```