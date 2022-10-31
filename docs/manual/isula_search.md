# isula search Manual
This manual is mainly about how to use isula search for iSulad community developers and users.
##   Start iSulad

Modify isulad `daemon.json` and config registry-mirrors:

```sh
$ vim /etc/isulad/daemon.json
	...
  "registry-mirrors": [
        "docker.io"
    ],
    ...
```

**tips**：
1. If you do not specify registry when using `isula search`, the registry configured in `daemon.json` is used by default.

2. If you want to use the http protocol to access the registry, you also need to add the registry to the insecure-registries in `daemon.json`:

```sh
"insecure-registries": [
    ],
```

Start isulad with root privileges：

```sh
$ isulad
```

## Use isula search

###  Discription

Search registry for images information.

### Usage

```
isula search [OPTIONS] TERM
```

### Options

| Name,shorthand        | Discription                                                         |
| ----------- | ------------------------------------------------------------ |
| --limit     | Max number of search results |
| --no-trunc  | Dont't truncate output |
| --filter,-f | Filter output based on conditions provided |
| --format    | Format the output using the given go template                                               |

## Example

### Search images by name


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

### Display non-truncated description

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

### Limit search results

```sh
$isula search --limit=1 busybox

NAME                            DESCRIPTION                                             STARS   OFFICIAL        AUTOMATED 
busybox                         Busybox base image.                                     2789    [OK]                   
```

### Filtering

The filtering flag (-f or --filter) format is a key=value pair. If there is more than one filter, then pass multiple flags (e.g. --filter is-automated=true --filter stars=3)

The currently supported filters are:

- stars(int)：Limit number of stars for the image.
- is-automated (boolean - true or false) :is the image automated or not.
- is-official (boolean - true or false) ：is the image official or not.

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

### Format the output

The formatting option (--format) pretty-prints search output using a Go template.

Valid placeholders for the Go template are:

| Placeholder         | Description                         |
| :------------- | :--------------------------- |
| `.Name`        | Image Name                     |
| `.Description` | Image description                     |
| `.StarCount`   | Number of stars for the image             |
| `.IsOfficial`   | “OK” if image is official   |
| `.IsAutomated` | “OK” if image build was automated |

For example：

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