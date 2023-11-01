# isulad对接GPU容器 指南

本文以nvidia的GPU为例,指导iSulad社区开发者和使用者使用isulad创建GPU容器。

### 安装nvidia-container-toolkit

安装详情可参考：https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html

### iSulad配置

在配置文件(/etc/isulad/daemon.json)中配置runtimes，在其中指定使用的runtime的`path`(nvidia-container-runtime二进制路径)以及`runtime-args`(对runtime所有命令配置的参数)。
```json
"runtimes": {
	"nvidia": {
		"path": "/usr/bin/nvidia-container-runtime",
		"runtime-args": []
	}
},
```

修改配置文件后，重启isulad
### 启动GPU容器

创建容器时指定容器运行时为`nvidia`即可：
```sh
isula run -tid --runtime=nvidia -e NVIDIA_VISIBLE_DEVICES=1,2 ubuntu:18.04 bash
```

### 未来规划

1. 后续版本中isulad将使用支持K8S的CDI接口来管理GPU
