[中文版入口](README_zh.md)

<img src="./logo/iSulad-logo.svg" alt="iSulad" style="max-width: 50%;" />

<a href="https://github.com/openeuler-mirror/iSulad"><img src="https://img.shields.io/badge/github-iSulad-blue"/></a> ![license](https://img.shields.io/badge/license-Mulan%20PSL%20v2-blue) ![language](https://img.shields.io/badge/language-C%2FC%2B%2B-blue)

## Introduction

`iSulad` , written in C/C++, is a lightweight container engine that has the advantage of being light, fast and applicable to multiple hardware specifications and architecture. `iSulad` has a wide application prospect. 

## Architecture

You can see `iSulad`  architecture in [architecture](./docs/design/architecture.md).

## Function

### Runtime

`iSulad` support multiple container runtimes, including lxc、runc and kata.

#### lxc

lxc is an open-source container  runtime written in C , which occupies less resources and is suitable for scenarios with high restrictions on noise floor resources. It is the default runtime of iSulad.

#### runc

runc is an OCI-compliant runtime written in GO. When users use runc, the OCI runtime-spec version is required to be at least 1.0.0.

#### kata-runtime

kata-runtime start secure containers with lightweight virtual machines.

### Image

`iSulad` supports multiple image formats, including OCI, external rootfs and embedded image.

#### OCI

OCI is a docker-compatible image format that supports pulling images and running containers from remote image repositories.

#### external rootfs

External rootfs allows users to prepare a bootable `root fs` directory, which is mainly used in system container scenarios.

#### embedded image

Embedded image is a unique embedded image format of `iSulad`, which occupies low resources and is mainly used in embedded application scenarios.

### Operation Interface

`iSulad` provides two different interfaces for image and container management operations: CLI and CRI.

#### CLI

CLI uses the command line to manage images and containers. It is a standard C/S architecture model. iSula performs as an independent command line client that talks to the iSulad daemon.

The commands provided by iSula cover most of the common application scenarios, including the operation interface of the container, such as run, stop, rm, pause, etc, as well as the related operations of the image, such as pull, import, rmi, etc.

#### CRI

CRI (Container Runtime Interface) implementer can work seamlessly with K8s.

CRI interface is implemented based on gRPC. iSulad implemented CRI gRPC Server following CRI interface standards. CRI gRPC Server includes runtime service and image service, which are used to provide container runtime interface and image operation interface respectively. CRI gRPC Server listen on a local unix socket, and the K8s component kubelet runs as a gRPC Client.

## Getting Started

- [usage guide: openeuler official manual](https://docs.openeuler.org/zh/docs/22.03_LTS/docs/Container/container.html)

- [development guide](./docs/build_docs/README.md)

- [user manual](./docs/manual/README.md)

- [design docs](./docs/design/README.md)

### Installing

To install `iSulad`, you can use `yum` package manager command with `openEuler` repository.

Or write repository file by hand:

```shell
$ cat << EOF > /etc/yum.repos.d/openEuler.repo
[openEuler]
baseurl=https://repo.openeuler.org/openEuler-22.03-LTS/OS/\$basearch
enabled=1
EOF
```

Install `iSulad` with yum:

```shell
$ yum install -y iSulad
```

if you found this error 

```txt
Repository 'openEuler' is missing name in configuration, using id.

You have enabled checking of packages via GPG keys. This is a good thing.
However, you do not have any GPG public keys installed. You need to download
the keys for packages you wish to install and install them.
You can do that by running the command:
    rpm --import public.gpg.key


Alternatively you can specify the url to the key you would like to use
for a repository in the 'gpgkey' option in a repository section and YUM
will install it for you.

For more information contact your distribution or package provider.
```

you should run `rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-openEuler` first.

### Configure

Configure the container image registry address, for example "docker.io" or other registry addrss.

```shell
# cat /etc/isulad/daemon.json
.....
    "registry-mirrors": [
        "docker.io"
    ],
.....
```

### Run

`iSulad` provides two ways to start the isulad:

1. Use `systemd` service to start `iSulad`:

```shell
# restart the server with systemd command
$ systemctl restart isulad 
```

2. Use direct command to start `iSulad`:

```shell
# run the server with default socket name and default log level and images manage function
$ sudo isulad 
```

###  Operations on containers

`iSulad` provides two operation interfaces for managing images and containers: CLI and CRI.

#### **CLI**

CLI, `iSulad` provides `isula` as client CLI

Here are some sample commands to manager containers.

- List all containers in your own environment:

```shell
$ sudo isula ps -a
```

- Create a container with busybox:

  - You can create container `test` with default runtime:

  ```sh
  $ sudo isula create -t -n test busybox
  ```

  - You also can create container `testrunc` with **runc runtime**:

  ```sh
  $ sudo isula create -t --runtime runc -n testrunc busybox
  ```


- Start this container `test`:

```shell
$ sudo isula start test
```

- Kill the container `test`:

```shell
$ sudo isula kill test
```

- Remove the container `test`:

```shell
$ sudo isula rm test
```

#### CRI

`iSulad` can be integrated with kubernetes through the CRI interface. For integrating with kubernetes, please refer to [k8s_integration](./docs/manual/k8s_integration.md).

##  Performance

Using [ptcr](https://gitee.com/openeuler/ptcr) as a performance test tool , it shows the performance of `iSulad` in computers with different architectures.

###  ARM

- For searially with 10 containers, the performance radar chart of `iSula`, `docker`, `podman` is as follows:

<img src="./docs/images/performance_arm_seri.png" alt="ARM searially" style="zoom:80%;" />

- For parallerlly with 100 containers, the performance radar chart of `iSula`, `docker`, `podman` is as follows:

<img src="./docs/images/performance_arm_para.png" alt="ARM parallerlly" style="zoom:80%;" />

### X86

- For searially with 10 containers, the performance radar chart of `iSula`, `docker`, `podman` is as follows:

<img src="./docs/images/performance_x86_seri.png" alt="X86 searially" style="zoom:80%;" />

- For parallerlly with 100 containers, the performance radar chart of `iSula`, `docker`, `podman` is as follows:

<img src="./docs/images/performance_x86_para.png" alt="X86 parallerlly" style="zoom:80%;" />

**More information can get from:**  [Performance test](https://gitee.com/openeuler/iSulad/wikis/Performance?sort_id=5449355)

## Kernel Requirements

`iSulad` runs on Kernels above 3.0.x.

## Compatibility

The standard specification versions that `iSulad` is compatible with are as follows:

- Compatible with OCI 1.0.0.
- Compatible with CNI 0.3.0 and above.
- Compatible with lcr 2.1.x and above.