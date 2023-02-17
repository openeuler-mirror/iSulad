# runc使用指南
本文主要是指导iSulad社区开发者和使用者，如何配置isulad使用runc作为runtime创建容器。

## 一、runc的安装

`tips`: 在安装runc之前需要安装好go环境。

isulad当前推荐的runc验证版本为v1.0.0-rc5。

runc可以使用以下两种安装方式：

1. 直接使用包管理器安装runc:

```sh
# centOS
sudo yum install runc
# Ubuntu
sudo apt-get install runc
```

2. 源码编译安装runc（注意建议切换成isulad推荐的runc版本：`git checkout v1.0.0-rc5`）

```sh
# 在GOPATH/src下创建 'github.com/opencontainers' 文件夹 
cd github.com/opencontainers
git clone https://github.com/opencontainers/runc
cd runc

make
sudo make install
```

还可以使用go get安装到`GOPATH`路径下（需要在GOPATH/src下创建github.com父文件夹）：

```sh
go get github.com/opencontainers/runc
cd $GOPATH/src/github.com/opencontainers/runc
make
sudo make install
```

最终安装好的runc会在`/usr/local/sbin/runc`目录下。

##   二、配置iSulad使用runc

### 配置文件配置

1. 修改isulad的daemon.json，配置isulad默认使用的runtime。

```sh
$ vim /etc/isulad/daemon.json
	...
   "default-runtime": "runc"
    ...
```

2. 也可以在配置文件中配置runtimes，在其中指定使用的`path`(用于修改isulad使用的runc路径)以及`runtime-args`(对runtime所有命令配置的参数)。

```sh
"runtimes": {
            "runc": {
                    "path": "/usr/local/sbin/runc",
                    "runtime-args": [
                    ]
            }
    },
```

之后使用root权限启动isulad服务，使修改后的配置生效即可：

```sh
$ sudo isulad
```

### 单个容器配置

使用`--runtime=runc`启动一个runtime为runc的容器。

```sh
isula run -tid -n test --runtime=runc busybox sh
```

## 三、K8s中配置pod的runtime为runc

如何与kubernetes集成请参考[k8s_integration](https://gitee.com/openeuler/iSulad/blob/master/docs/manual/k8s_integration_zh.md)。

### 全局配置

直接参照第二节中配置文件配置的方式修改isulad默认使用的runtime为runc，则后续使用k8s启动容器时会默认使用的runtime即为runc。

### 使用RuntimeClass配置

RuntimeClass 是K8s的一种内置集群资源，是一种容器运行时配置，用于运行pod中的容器。

1. 在`/etc/isulad/daemon.json`中配置`isulad`：

   ```json
   "runtimes": {
               "runc-runtime": {
                       "path": "/usr/local/sbin/runc",
                       "runtime-args": [
                       ]
               }
       },
   ```

2. 定义 `runc-runtime.yaml`，例如创建一个`runc-runtime.yaml`内容如下：(注意handler需要与daemon.json中的名称一致)

   ```yamlapiVersion: v1
   apiVersion: node.k8s.io/v1beta1
   kind: RuntimeClass
   metadata:
     name: runc-runtime
   handler: runc-runtime
   ```

   之后运行`kubectl apply -f runc-runtime.yaml`命令在kubectl中让这个配置生效。

3. 之后在创建pod时，可以在其定义的yaml文件中的`spec.runtimeClassName`中设置pod使用的runtime：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: runc-pod-example
spec:
  runtimeClassName: runc-runtime
  containers:
  - name: runc-pod
    image: busybox:latest
    command: ["/bin/sh"]
    args: ["-c", "sleep 1000"]
```

