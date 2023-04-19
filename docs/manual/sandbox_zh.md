| Author | 徐学鹏 |
| ------ | ---- |
| Date   |  2023-04-18     |
| Email   |    xuxuepeng1@huawei.com    |

# Sandboxer使用指南
本文主要指导iSulad社区的开发者和使用者，如何使能iSulad的Sandbox API接口。

## 安装iSulad
目前Sandbox API的代码，仅在iSulad和lcr的dev-sandbox分支进行迭代演进。在iSulad中使用了编译宏进行隔离。iSulad依赖环境的安装请参考文档`docs/build_docs/guide/build_guide_zh.md`，此处不再赘述。下面仅对lcr，lib-shim-v2和iSulad的编译进行说明。

在安装完依赖后，需要确保系统中有make命令，如果缺失，可以使用如下命令安装make命令。
```bash
dnf install make
```

在编译之前，需要设置一下ldconfig和pkgconfig的路径。具体可以参考[build_guide_zh.md](../build_docs/guide/build_guide_zh.md#设置ldconfig和pkgconfig的路径)

### 编译安装lcr
```bash
# build and install lcr
$ git clone https://gitee.com/openeuler/lcr.git
$ cd lcr
# dev-sandbox分支
$ git checkout dev-sandbox
$ mkdir build
$ cd build
$ cmake ..
$ make -j $(nproc)
$ make install
```

### 编译安装lib-shim-v2
lib-shim-v2是Rust编写的，因此编译需要先准备好Rust的编译环境。

Rust的安装可以参见[Rust官网](https://www.rust-lang.org/tools/install)，或者通过一下命令安装。

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

```bash
# build and install lib-shim-v2
$ git clone https://gitee.com/openeuler/lib-shim-v2.git
$ cd lib-shim-v2
# master分支
$ make
$ make install
```

### 编译安装使能Sandbox API的iSulad
iSulad的编译安装过程中可能会使用到tar命令。如果缺失可以通过以下命令安装。
```bash
dnf install tar
```

```bash
# build and install iSulad
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
# dev-sandbox分支
$ git checkout dev-sandbox
$ mkdir build
$ cd build
$ cmake -DENABLE_SANDBOX=ON -DENABLE_SHIM_V2=ON ..
$ make -j $(nproc)
$ make install
```

## 安装Kuasar
Kuasar是由Rust编写的，因此与lib-shim-v2一样，需要准备好Rust的编译环境，此处就不再赘述。
Kuasar支持多种形态的Sandboxer。此处以stratovirt为例，编译vmm类型的Kuasar Sandboxer。

```bash
# build and install kuasar
$ git clone https://github.com/kuasar-io/kuasar.git
$ cd kuasar
$ export HYPERVISOR=stratovirt
$ make vmm
$ make install-vmm
```
Kuasar相关安装流程可参考[Kuasar文档](https://github.com/kuasar-io/kuasar/blob/main/docs/vmm/how-to-run-kuasar-with-isulad-and-stratovirt.md)。

## 安装stratovirt
上述编译的Kuasar Sandboxer使用轻量级虚拟机stratovirt作为沙箱，需要安装stratovirt。

```bash
dnf install stratovirt
```

如果使用的Linux发行版没有stratovirt的安装包，可以参考[stratovirt用户说明](https://gitee.com/openeuler/stratovirt/blob/master/README.ch.md)进行编译安装。

## 安装crictl工具
crictl是CRI客户端工具，可以用于发送CRI请求，安装可以参见[官方说明](https://github.com/kubernetes-sigs/cri-tools/blob/master/docs/crictl.md#install-crictl)。

## 配置Kuasar
以stratovirt为例，配置Kuasar运行时。
```toml
  [sandbox]

  [hypervisor]                                                                                                               
  path = "/usr/bin/stratovirt"                                                                                               
  machine_type = "virt,mem-share=on"                                                                                         
  kernel_path = "/var/lib/kuasar/vmlinux.bin"                                                                                     
  image_path = ""                                                                                                            
  initrd_path = "/var/lib/kuasar/kuasar.initrd"                                              
  kernel_params = "task.log_level=debug task.sharefs_type=virtiofs"                                                          
  vcpus = 1                                                                                                                  
  memory_in_mb = 1024                                                                                                        
  block_device_driver = "virtio-blk"                                                                                         
  debug = true
  
  [hypervisor.virtiofsd_conf]                                                                                                
  path = "/usr/bin/vhost_user_fs
```

## 配置iSulad

修改iSulad daemon.json文件，配置sandboxer。

```json
{	...
    "default-sandboxer": "vmm",
    "sandboxers": {
        "vmm": {
            "address": "/run/vmm-sandboxer.sock",
            "controller": "proxy",
            "protocol": "grpc"
        }
    },
    "cri-runtimes": {
        "vmm": "io.containerd.vmm.v1"
    },
    ...
}

```

## 启动Kuasar

```bash
$ RUST_LOG=debug vmm-sandboxer --listen /run/vmm-sandboxer.sock --dir /kuasar
```

## 启动iSulad

```bash
$ isulad
```

## 配置crictl工具

修改crictl配置文件/etc/crictl.yaml。

```yaml
runtime-endpoint: unix:///var/run/isulad.sock
image-endpoint: unix:///var/run/isulad.sock
timeout: 10
```

## 使用Sandbox

### 创建Pod
创建Pod配置文件pod.json
```json
{
    "metadata": {
        "name": "test-pod",
        "namespace": "default"
    },
    "log_directory": "/tmp",
    "linux": {
        "security_context": {
            "namespace_options": {
                "network": 2,
                "pid": 1
            }
        }
    }
}
```

使用crictl工具指定使用vmm作为runtime创建pod。

```bash
$ pod_id=`crictl runp --runtime=vmm pod.json`
```

### 创建并运行container

创建一个container配置文件

```json
{
    "metadata": {
        "name": "ubuntu",
        "namespace": "default"
    },
    "image": {
      "image": "ubuntu:latest"
    },
    "command": [
       "/bin/sh", "-c", "while true; do echo \`date\`; sleep 1; done"
    ],
    "log_path":"ubuntu.log",
    "linux": {
        "security_context": {
            "namespace_options": {
                "network": 2,
                "pid": 1
            }
        }
    }
}
```

在pod中创建上述容器
```bash
$ container_id=`crictl run --runtime="vmm" container.json pod.json`
```

### 停止并删除container
```bash
$ crictl stop $container_id
$ crictl rm $container_id
```

### 停止并销毁Pod
```bash
$ crictl stopp $pod_id
$ crictl rmp $pod_id
```
