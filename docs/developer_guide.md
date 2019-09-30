# 警告

本文档专为开发人员编写：不适用于最终用户。

# 假设

- 您正工作在一台正常运转的测试或开发机器上。

# 创建开发环境

您可以使用下面两种方式创建开发环境。

## 在主机上安装iSulad

推荐的方式是在您的主机上[安装iSulad的依赖组件](http://code.huawei.com/containers/iSulad/blob/cri/documentation/install_guide.md)，安装手册将指导您安装所有iSulad必须的组件，包括protobuf、gRPC、lxc、lcr、iSulad等。

## 在容器中安装iSulad

### 依赖

在主机上安装docker。

下载[crictl-1.0.0-alpha.1](https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.0.0-alpha.1/crictl-1.0.0-alpha.1-linux-amd64.tar.gz)并放置于`/root/golang`路径下。

```sh
$ ls /root/golang/
crictl-1.0.0-alpha.1-linux-amd64.tar.gz
```

您可能还需要配置insecure-registry以下载dockerhub的镜像。

- 对于centos，在` /etc/sysconfig/docker`文件中添加`OPTIONS='--insecure-registry rnd-dockerhub.huawei.com'`
- 对于ubuntu，在` /etc/docker/daemon.json`中添加`{\"insecure-registries\":[\"rnd-dockerhub.huawei.com\"]}`

### 安装

```sh
$ ./CI/prepare_compile_env.sh
```

脚本执行完后，将运行一个名为`isulad-compile-env-$commit`的容器，您可以执行`docker exec -it isulad-compile-env-$commit /bin/bash`命令进入该容器，iSulad的源码在容器内的根目录`/isulad`下。

# 编码风格

首先您应该安装[Artistic Style](http://astyle.sourceforge.net)。

## 检查代码风格

修改完代码后，通过以下命令查看是否存在代码风格问题。

```sh
$ ./tools/check-syntax
```

## 修复代码风格

修改完代码后，通过以下命令尝试修复代码风格问题。

```sh
$ ./tools/check-syntax -f
```

# 修改Proto文件

如果涉及gRPC接口变更，需修改`./src/api/services/`下的[Proto](https://developers.google.com/protocol-buffers/docs/proto3)文件。修改完成后，重新[编译iSulad](http://code.huawei.com/containers/iSulad/blob/cri/documentation/install_guide.md#build-lcrd)。

# 添加json-schema文件

当您需要解析新的json文件时，要在`src/json/schema/schema`路径下添加[json-schema](http://json-schema.org)文件，具体要求参考[iSula_C-json反射脚本使用说明](http://code.huawei.com/iSula/MayTheForceBeWithYou/blob/master/isulad/iSula%20C-Json%E5%8F%8D%E5%B0%84%E8%84%9A%E6%9C%AC%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E.docx)。

# 如何写commit message

如果提交了测试脚本的MR，需要在iSulad的commit信息中，添加测试脚本MR的信息。在commit信息的reason后面，添加一行，command: "测试脚本MR的路径和分支"。示例如下：

```sh
isulad: xxxxx

DTS/AR: XXXX
reason: xxxxx
command: "git fetch http://code-sh.rnd.huawei.com/xxxxxxxxx/isula_testcases.git console"
```
