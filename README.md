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


### Build from source
Build requirements for developers are listed in [build_guide](./docs/build_guide.md)

## Performance

#### Machine configuration

X86 machine:

| Configuration | Information                                  |
| ------------- | -------------------------------------------- |
| OS            | Fedora32 X86_64                              |
| Kernel        | linux 5.7.10-201.fc32.x86_64                 |
| CPU           | 48 cores，Intel Xeon CPU E5-2695 v2 @ 2.4GHZ |
| Memory        | 132 GB                                       |

ARM machine:

| Configuration | Information   |
| ------------- | ------------- |
| OS            | openEuler     |
| Kernel        | linux 4.19.90 |
| CPU           | 64 cores      |
| Memory        | 196 GB        |

#### Version of Softwares

| Name      | Version                                                                |
| --------- | ---------------------------------------------------------------------- |
| iSulad    | Version:	2.0.3 , Git commit:  3bb24761f07cc0ac399e1cb783053db8b33b263d |
| docker    | Version:    19.03.11, Git commit:   42e35e6                            |
| podman    | version 2.0.3                                                          |
| CRI-O     | v1.15.4                                                                |
| kubelet   | v1.15.0                                                                |
| cri-tools | v1.15.0                                                                |

#### Design of testcase

![design of performance test](./docs/images/performan_test_design.png)

About code of test

- [x] Now, we use shell to finish test cases of performance;

- [ ] Future, we should have a repository which store all test cases for iSula. Such as, performance tests, validation tests and so on... [It's coming soon](https://gitee.com/openeuler/iSulad/wikis/2020-%E4%B8%8B%E5%8D%8A%E5%B9%B4%E7%89%B9%E6%80%A7%E8%B7%AF%E6%A0%87?sort_id=2471417)...

#### Compare with other container engines

##### run operator once

###### X86

base operators of client

| operator (ms) | Docker | Podman | iSulad | vs Docker | vs Podman |
| ------------- | ------ | ------ | ------ | --------- | --------- |
| create        | 287    | 180    | 87     | -69.69%   | -51.67%   |
| start         | 675    | 916    | 154    | -77.19%   | -83.19%   |
| stop          | 349    | 513    | 274    | -21.49%   | -46.59%   |
| rm            | 72     | 187    | 60     | -16.67%   | -67.91%   |
| run           | 866    | 454    | 195    | -77.48%   | -57.05%   |

base operators of CRI

| operator (ms) | Docker | CRIO | iSulad | vs Docker | vs CRIO |
| ------------- | ------ | ---- | ------ | --------- | ------- |
| runp          | 681    | 321  | 186    | -72.69%   | -42.06% |
| stopp         | 400    | 356  | 169    | -57.75%   | -52.53% |

###### ARM

base operators of client

| operator (ms) | Docker | Podman | iSulad | vs Docker | vs Podman |
| ------------- | ------ | ------ | ------ | --------- | --------- |
| create        | 401    | 361    | 61     | -84.79%   | -83.10%   |
| start         | 1160   | 1143   | 232    | -80.00%   | -79.70%   |
| stop          | 634    | 576    | 243    | -61.67%   | -57.81%   |
| rm            | 105    | 398    | 46     | -56.19%   | -88.44%   |
| run           | 1261   | 1071   | 258    | -79.54%   | -75.91%   |

base operators of CRI

| operator (ms) | Docker | CRIO | iSulad | vs Docker | vs CRIO |
| ------------- | ------ | ---- | ------ | --------- | ------- |
| runp          | 1339   | 2366 | 179    | -86.63%   | -92.43% |
| stopp         | 443    | 419  | 117    | -73.59%   | -72.08% |

##### parallel to run operator 100 times

###### X86

base operator of client

| operator (ms) | Docker | Podman | iSulad | vs Docker | vs Podman |
| ------------- | ------ | ------ | ------ | --------- | --------- |
| 100 * create  | 4995   | 3993   | 829    | -83.40%   | -79.24%   |
| 100 * start   | 10126  | 5537   | 1425   | -85.93%   | -74.26%   |
| 100 * stop    | 8066   | 11100  | 2273   | -71.82%   | -79.52%   |
| 100 * rm      | 3220   | 4319   | 438    | -86.40%   | -89.86%   |
| 100 * run     | 9822   | 5979   | 2117   | -78.45%   | -64.59%   |

base operators of CRI

| operator (ms) | Docker | CRIO | iSulad | vs Docker | vs CRIO |
| ------------- | ------ | ---- | ------ | --------- | ------- |
| 100 * runp    | 13998  | 4946 | 2825   | -79.82%   | -42.88% |
| 100 * stopp   | 8402   | 4834 | 4543   | -45.93%   | -6.02%  |

###### ARM

base operator of client

| operator (ms) | Docker | Podman | iSulad | vs Docker | vs Podman |
| ------------- | ------ | ------ | ------ | --------- | --------- |
| 100 * create  | 14563  | 12081  | 538    | -96.31%   | -95.55%   |
| 100 * start   | 23420  | 15370  | 1841   | -92.14%   | -88.02%   |
| 100 * stop    | 22234  | 16973  | 930    | -95.82%   | -94.52%   |
| 100 * rm      | 937    | 10493  | 233    | -75.13%   | -97.78%   |
| 100 * run     | 28091  | 16280  | 2320   | -91.74%   | -85.75%   |

base operators of CRI

| operator (ms) | Docker | CRIO  | iSulad | vs Docker | vs CRIO |
| ------------- | ------ | ----- | ------ | --------- | ------- |
| 100 * runp    | 27802  | 29197 | 2398   | -91.37%   | -91.79% |
| 100 * stopp   | 14429  | 11173 | 1170   | -91.89%   | -89.53% |

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