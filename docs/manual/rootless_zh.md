| Author | 刘昊 |
| ------ | ---- |
| Date   |  2022-10-08     |
| Email   |    liuhao27@huawei.com    |

# 使用非root运行iSulad

`非root` 用户可以基于 [user_namespaces(7)](http://man7.org/linux/man-pages/man7/user_namespaces.7.html) 机制运行 `iSulad`。

若您需要实现非root运行iSulad，可以使用 [rootlesskit](https://github.com/rootless-containers/rootlesskit) 快速搭建环境。

**注意：该功能作为实验特性，不建议商用！！！**

## 环境要求

- 主机使能cgroup V2；
- `overlayfs` 要求内核高于5.11；

## rootlesskit安装方法

参考官方文档：https://github.com/rootless-containers/rootlesskit

## 手动方式

### 修改文件权限

由于安全原因，iSulad的配置文件权限均去掉others权限，且属主为root，因此如果是普通用户需要修改对应权限。

```bash
$ chmod +r /etc/isulad/*
$ chmod +r /etc/default/isulad/*
$ chmod +r /etc/default/isulad/hooks/*
```

### 删除临时文件

如果主机上之前运行过iSulad，需要删除之前的残留目录，否则会导致rootless的iSulad无权限操作这些目录。

```bash
$ rm -rf /var/run/isula /var/run/isulad /var/run/lxc
```

### 修改配置文件

```bash
$ cat /etc/isulad/daemon.json
{
    "group": "isula",
    "default-runtime": "lcr",
    "graph": "/home/xxxx/rootless",
    "state": "/run/user/1000/rootlesskit-isulad",
    "engine": "lcr",
    "log-level": "ERROR",
    "pidfile": "/run/user/1000/rootlesskit-isulad/isulad.pid",
    "log-opts": {
        "log-file-mode": "0600",
        "log-path": "/home/xxxx/rootless",
        "max-file": "1",
        "max-size": "30KB"
    },
    "log-driver": "file",
    "container-log": {
        "driver": "json-file"
    },
    "hook-spec": "/etc/default/isulad/hooks/default.json",
    "start-timeout": "2m",
    "storage-driver": "overlay2",
    "storage-opts": [
        "overlay2.override_kernel_check=true"
    ],
    "registry-mirrors": [
    ],
    "insecure-registries": [
    ],
    "pod-sandbox-image": "",
    "native.umask": "normal",
    "network-plugin": "",
    "cni-bin-dir": "",
    "cni-conf-dir": "",
    "image-layer-check": false,
    "use-decrypted-key": true,
    "insecure-skip-verify-enforce": false,
    "cri-runtimes": {
        "kata": "io.containerd.kata.v2"
    }
}
```

### 使用非root用户启动isulad

```bash
$ rootlesskit --cgroupns --copy-up=/run --copy-up=/usr/local --state-dir=/run/user/1000/rootlesskit-isulad bash
$ isulad -H "unix:///run/user/1000/rootlesskit-isulad/isulad.sock" &
```

### 运行容器

```bash
$ nsenter -U --preserve-credentials -m -t $(cat /run/user/1000/rootlesskit-isulad/child_pid)
$ export ISULAD_HOST="unix:///run/user/1000/rootlesskit-isulad/isulad.sock"
$ isula run -tid openeuler-22.03-lts bash
```

### 验证

在主机查看 `isula` 相关进程信息：

```bash
$ ps aux |grep isula
haozi      79488  0.0  0.0 1228192 8684 pts/5    Sl   17:31   0:00 rootlesskit --cgroupns --copy-up=/run --copy-up=/usr/local --state-dir=/run/user/1000/rootlesskit-isulad bash
haozi      79494  0.0  0.0 1228192 7992 pts/5    Sl   17:31   0:00 /proc/self/exe --cgroupns --copy-up=/run --copy-up=/usr/local --state-dir=/run/user/1000/rootlesskit-isulad bash
haozi      81279  0.0  0.0 1321272 28892 pts/5   Sl   17:43   0:00 isulad -H unix:///run/user/1000/rootlesskit-isulad/isulad.sock
root       83798  0.0  0.0 222300  2164 pts/1    S+   18:01   0:00 grep --color=auto isula
```

**可以看到，isulad和容器的进程属主，均为haozi普通用户，而非root。**


## TODO

- 自动化部署工具；
- 完善 `oci runtime` 的rootless支持；