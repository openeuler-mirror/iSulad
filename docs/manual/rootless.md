| Author | liuhao  |
| ------ | ---- |
| Date   |  2022-10-08     |
| Email   |    liuhao27@huawei.com    |

# Run isulad with a non-root user

`Non-root user` can run `iSulad` based on [user_namespaces(7)](http://man7.org/linux/man-pages/man7/user_namespaces.7.html).

If you want to run isulad with a non-root user，you can quickly build the environment by using [rootlesskit](https://github.com/rootless-containers/rootlesskit).

**Tips: this method is an experimental feature and is not recommended for commercial use！**

## Requirements

- Host enabled cgroup V2；
- `overlayfs` requires a kernel above 5.11；


## Starting from scratch

### Install rootlesskit

Reference to official documents：https://github.com/rootless-containers/rootlesskit.

### Modify file permissions

For security, files in iSulad remove other permissions and the owner is root, so if you are a non-root user, you need to modify the corresponding permissions.

```bash
$ chmod +r /etc/isulad/*
$ chmod +r /etc/default/isulad/*
$ chmod +r /etc/default/isulad/hooks/*
```

### Delete temporary files

If iSulad has been run on the host before, you need to delete the remaining directories, otherwise iSulad of rootless will not have permission to operate these directories.

```bash
$ rm -rf /var/run/isula /var/run/isulad /var/run/lxc
```

### Modify configuration file

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

### Run isulad

```bash
$ rootlesskit --cgroupns --copy-up=/run --copy-up=/usr/local --state-dir=/run/user/1000/rootlesskit-isulad bash
$ isulad -H "unix:///run/user/1000/rootlesskit-isulad/isulad.sock" &
```

### Run container

```bash
$ nsenter -U --preserve-credentials -m -t $(cat /run/user/1000/rootlesskit-isulad/child_pid)
$ export ISULAD_HOST="unix:///run/user/1000/rootlesskit-isulad/isulad.sock"
$ isula run -tid openeuler-22.03-lts bash
```

### verify

List the information about processes associated with 'isula':

```bash
$ ps aux |grep isula
haozi      79488  0.0  0.0 1228192 8684 pts/5    Sl   17:31   0:00 rootlesskit --cgroupns --copy-up=/run --copy-up=/usr/local --state-dir=/run/user/1000/rootlesskit-isulad bash
haozi      79494  0.0  0.0 1228192 7992 pts/5    Sl   17:31   0:00 /proc/self/exe --cgroupns --copy-up=/run --copy-up=/usr/local --state-dir=/run/user/1000/rootlesskit-isulad bash
haozi      81279  0.0  0.0 1321272 28892 pts/5   Sl   17:43   0:00 isulad -H unix:///run/user/1000/rootlesskit-isulad/isulad.sock
root       83798  0.0  0.0 222300  2164 pts/1    S+   18:01   0:00 grep --color=auto isula
```

**The process owner of isulad and the container are both non-root user haozi.**


## TODO

- Automated deployment tools.
- Improve the rootless support of 'oci runtime'.