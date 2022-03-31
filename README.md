<img src="logo/isula-logo.png" alt="iSulad" style="zoom:80%;" />

## iSulad

`iSulad` is a lightweight container runtime daemon which is designed for IOT and Cloud infrastructure.`iSulad` has the characteristics of light, fast and not limited by hardware specifications and architecture, and can be applied more widely.

## Documentation

- [en build guide](./docs/build_guide.md)
- [cn build guide](./docs/build_guide_zh.md)
- [more usage guide](https://openeuler.org/zh/docs/20.09/docs/Container/iSula%E5%AE%B9%E5%99%A8%E5%BC%95%E6%93%8E.html)

## Getting Started

### Installing

To install iSulad, you can use `rpm` or `yum` package manager command with `openEuler` repository.

Or write repository file by hand:

```sh
cat << EOF > /etc/yum.repos.d/openEuler.repo
[openEuler]
baseurl=https://repo.openeuler.org/openEuler-20.03-LTS/OS/\$basearch
enabled=1
EOF
```

Install iSulad with yum:

```sh
yum install -y iSulad
```

if you found this error 
```
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

you should run `rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-openEuler` first


### Configure

Configure the container image registry address, for example "docker.io" or other registry addrss.

```sh
# cat /etc/isulad/daemon.json
.....
    "registry-mirrors": [
        "docker.io"
    ],
.....
```

### Run

We provide `systemd` service to start `iSulad`:
```sh
systemctl restart isulad # restart the server with systemd command
```

You can use direct command to start `iSulad` server：
```sh
$ sudo isulad  # run the server with default socket name and default log level and images manage function
```
### Operations on containers:

For more informations on how to use `iSulad`, please refer to the [guide](https://openeuler.org/en/docs/20.03_LTS/docs/Container/isulad-container-engine.html)

`iSulad` provides two operate interfaces to manager images and containers.

- CLI, `iSulad` provides `isula` as client CLI

    Here are some sample commands to manager containers.

    List all containers in your own environment:
    ```sh
    # list containers
    $ sudo isula ps -a
    ```

    Create a container with busybox named `test`:
    ```sh
    # create a container 'test' with image busybox
    $ sudo isula create -t -n test busybox
    ```

    Start this container `test`:
    ```sh
    # start the container 'test'
    $ sudo isula start test
    ```
    Kill the container `test`:
    ```sh
    # kill the container 'test':
    $ sudo isula kill test
    ```
    Remove the container `test`:
    ```sh
    # remove the container 'test'
    $ sudo isula rm test
    ```

- CRI interface, `iSulad` can be integrated with `kubernetes` through CRI interface

    How to integrate with `kubernetes` please refer to [integration.md](./docs/integration.md)

### Operations about native network

Operations about how to use native network, please refer to the [native_network.md](./docs/manual/native_network.md)

### Build from source
Build requirements for developers are listed in [build_guide](./docs/build_guide.md)

## Performance

Power by [ptcr](https://gitee.com/openeuler/ptcr)
### ARM Radar charts

#### searially with 10 containers

<img src="docs/images/performance_arm_seri.png" alt="ARM searially" style="zoom:80%;" />

#### parallerlly with 100 containers

<img src="docs/images/performance_arm_para.png" alt="ARM parallerlly" style="zoom:80%;" />

### X86 Radar chart

#### searially with 10 containers

<img src="docs/images/performance_x86_seri.png" alt="X86 searially" style="zoom:80%;" />

#### parallerlly with 100 containers

<img src="docs/images/performance_x86_para.png" alt="X86 parallerlly" style="zoom:80%;" />


**More information can get from:**  [Performance test](https://gitee.com/openeuler/iSulad/wikis/Performance?sort_id=5449355)

## Try to Use iSulad

If you want to experience iSulad right now, you can try to use it at：

- https://lab.huaweicloud.com/testdetail_498

It is the experiment about iSulad. In this experiment you can install iSulad easily. And then you can pull image, run container, analyse iSulad's performance and compare it with performance of Docker.

## How to Contribute

We always welcome new contributors. And we are happy to provide guidance for the new contributors.
iSulad follows the kernel coding conventions. You can find a detailed introduction at:

- https://www.kernel.org/doc/html/v4.10/process/coding-style.html

You can get more information about iSulad from our wikis, including roadmap, feature design documents, etc:

- https://gitee.com/openeuler/iSulad/wikis

## Licensing

iSulad is licensed under the Mulan PSL v2.

## Related Resouces

- [bilibili videos](https://space.bilibili.com/527064077/video?keyword=iSulad)
- [如何在openEuler树莓派镜像上部署k8s+iSula集群](https://my.oschina.net/openeuler/blog/4774838)
- [基于openEuler搭建部署k8s](https://bbs.huaweicloud.com/forum/forum.php?mod=viewthread&tid=94271)

## Join us
You can join us on any of the following channels:
* Join our [mailing list](https://mailweb.openeuler.org/postorius/lists/isulad.openeuler.org/)
* Join our Biweekly meeting at 16:30 pm on Tuesday (meeting link will be mailed at mailing list)