<img src="logo/isula-logo.png" alt="iSulad" style="zoom:80%;" />

## iSulad

`iSulad` is a light weight container runtime daemon which is designed for IOT and Cloud infrastructure.`iSulad` has the characteristics of light, fast and not limited by hardware specifications and architecture, and can be applied more widely.

## Getting Started

### Installing
To install iSulad, you can use `rpm` or `yum` package manager command with `openEuler` repository.

Install iSulad with yum
```sh
yum install -y iSulad
```

### Run
We provide `systemd` service to start `iSulad`
```sh
systemctl start isulad # run the server with systemd command
```

You can use direct command to start `iSulad` server：
```sh
$ sudo isulad  # run the server with default socket name and default log level and images manage function
```
### Operations on containers:
`iSulad` provides command line `isulad` to talk with server.
Here are some sample commands to manager containers.

List all containers in your own environment:
```sh
# list containers
$ sudo isula ps -a
```

Create a container with busybox named `test`
```sh
# create a container 'test' with image busybox
$ sudo isula create -t -n test busybox
```

Start this container `test`
```sh
# start the container 'test'
$ sudo isula start test
```
Kill the container `test`
```sh
# kill the container 'test'
$ sudo isula kill test
```
Remove the container `test`
```sh
# remove the container 'test'
$ sudo isula rm test
```

### Build from source
Build requirements for developers are listed in [build_guide](./docs/build_guide.md)

### Integration
Integrate with `kubenetes` are listed in [integration.md](./docs/integration.md)

## How to Contribute

We always welcome new contributors. And we are happy to provide guidance for the new contributors.
iSulad follows the kernel coding conventions. You can find a detailed introduction at:

- https://www.kernel.org/doc/html/v4.10/process/coding-style.html

## Licensing

iSulad is licensed under the Mulan PSL v1.
