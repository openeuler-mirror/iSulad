
# ISulad在RISC-V构架的openEuler的支持工作


---

## RISC-V虚拟环境的搭建
>RISC-V的环境我们是通过在host上使用QEMU虚拟机实现的，我们要做的是使用任意一Linux发行版作为host安装QEMU虚拟机，在虚拟机中启动RISC-V的openEuler镜像，在虚拟机镜像中完成iSulad的安装。
### 1. 安装虚拟机

首先是在host上安装QEMU，打开终端，依次输入以下命令：
```shell
wget https://download.qemu.org/qemu-5.1.0.tar.xz
tar xvJf qemu-5.1.0.tar.xz
cd qemu-5.1.0
./configure --target-list=riscv64-softmmu
make 
make install
```
### 2. 启动文件准备
安装好支持RISC-V的QEMU之后，就可以使用它来启动虚拟机的镜像，镜像的下载和安装可以参考[openEuler RISC-V 移植版的获取和运行](https://gitee.com/openeuler/RISC-V/blob/master/documents/Installing.md)，启动QEMU的虚拟机Linux环境，应该有以下几个文件：

1. [oe-rv-rv64g-30G.qcow2](https://isrc.iscas.ac.cn/mirror/openeuler-sig-riscv/images/oe-rv-rv64g-30G.qcow2)
  
2. [fw_payload_oe.elf](https://isrc.iscas.ac.cn/mirror/openeuler-sig-riscv/images/fw_payload_oe.elf)
  
3. run_oe1_rv64.sh(可选)
  

可以创建一个shell文件，内容来自[installing.md](https://gitee.com/openeuler/RISC-V/blob/master/documents/Installing.md)，如下：


```shell
#!/bin/sh

qemu-system-riscv64 \
    -machine virt \    
    -nographic \
    -smp 8 \
    -m 124G \
    -drive file=oe-rv-base-expand.qcow2,format=qcow2,id=hd0 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-device,rng=rng0 \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=usernet,hostfwd=tcp::12055-:22 \
    -device virtio-net-device,netdev=usernet \
    -append 'root=/dev/vda1 systemd.default_timeout_start_sec=600 selinux=0  rw highres=off console=ttyS0 mem=4096M earlycon' \
    -kernel fw_payload.elf  \
```

里面是一些参数的设定，可以查看QEMU的参数说明根据本地计算机配置进行调整。
### 3.启动虚拟机
可以采用两种方式：
1. 在终端直接输入shell文件中的内容
2. 如果创建了shell文件，只需要在终端里输入 `sh run_oe1_rv64.sh`

默认的登陆用户名/密码是：root/openEuler12#$

## 依赖安装

正式编译项目之前，要在系统上安装编译工具、代码版本控制等用途的软件包。
这个过程会使用yum工具来对rpm软件包进行安装，如果刚刚使用`oe-rv-rv64g-30G.qcow2`，里面并没有提供yum工具，可以使用下面的命令进行yum的安装：

```shell
wget https://isrc.iscas.ac.cn/mirror/openeuler-sig-riscv/oe-RISCV-repo/noarch/yum-4.2.15-8.noarch.rpm --no-check-certificate
rpm -ivh yum-4.2.15-8.noarch.rpm
```
之后，可以使用yum工具进行所需软件包的安装：
```shell
sudo yum --enablerepo='*' install -y automake autoconf libtool cmake make libcap libcap-devel libselinux libselinux-devel libseccomp libseccomp-devel yajl-devel git libcgroup tar python3 python3-pip device-mapper-devel libarchive libarchive-devel libcurl-devel zlib-devel glibc-headers openssl-devel gcc gcc-c++ systemd-devel systemd-libs libtar libtar-devel vim
```
软件包的所需依赖参考了[build_guide](https://gitee.com/openeuler/iSulad/blob/master/docs/build_guide.md),和参考文档相比，去掉了golang(iSulad转为全C开发，不再使用GO语言)，增加了vim(镜像没有文本编辑工具)。  
要修改yum源的配置，在 /etc/yum.repos.d/下打开`oe-rv.repo`文件，一般使用[Index of /oe-RISCV-repo/](https://isrc.iscas.ac.cn/mirror/openeuler-sig-riscv/oe-RISCV-repo/)为yum源的地址。

## 源码编译及安装
> 整个过程参考了[build_guide](https://gitee.com/openeuler/iSulad/blob/master/docs/build_guide.md)，编译过程中出现了一些错误，做了修改，整理成下面的编译指南。
### 正式编译之前的准备工作及提示
##### 1.设置 ldconfig and pkgconfig（若编译中断，再次进入系统时在源码编译之前都必须运行一次！）

```javascript
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
$ export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH
$ sudo -E echo "/usr/local/lib" >> /etc/ld.so.conf
```
##### 2.调整虚拟机时间为本地时间（否则编译的过程中会输出`Clock skew detected`的警告。这或许不是最好的方法，但却很简单有效，大家也可以自己找其他的方法消除警告）
时间调整命令的格式如下： date -s 2020-09-28

##### 3.建议创建一个合适的目录，如：build_isulad(后面编译的源码都将放在这个目录下面，每次`git clone`的时候，请先切换到此目录)
##### 4.protobuf、grpc需要匹配所用系统的编译器版本，如：grpc-1.22 不支持GCC 9+。由于目前使用的虚拟机下编译器版本都一致，这一点不需要考虑

### 源码编译安装protobuf（这部分的编译安装相对于参考的[build_guide](https://gitee.com/openeuler/iSulad/blob/master/docs/build_guide.md),做了比较大的调整，以满足后面的grpc能够顺利编译）
```javascript
$ pkg-config --cflags protobuf 
$ pkg-config --libs protobuf 
$ pkg-config --cflags --libs protobuf 


$ git clone https://gitee.com/src-openeuler/protobuf.git
$ cd protobuf
$ git checkout openEuler-20.03-LTS-tag
$ tar -xzvf protobuf-all-3.9.0.tar.gz
$ cd protobuf-3.9.0
```
> 此过程参考了[stack overflow](https://stackoverflow.com/questions/53586540/c-terminate-called-after-throwing-an-instance-of-stdsystem-error),如果按照[build_guide](https://gitee.com/openeuler/iSulad/blob/master/docs/build_guide.md)编译，在编译grpc时，会报` 'std::system_error'`这样的问题。
在编译之前要对文件做一些修改,使用如下命令打开protobuf源文件下的src/google/protobuf/stubs/common.cc文件：
```
vi src/google/protobuf/stubs/common.cc
```
在这个文件中，把有关 _WIN32 的所有代码都注释掉,如下：
```
// updated by Aimer on linux platform

//#ifdef _WIN32
//#define WIN32_LEAN_AND_MEAN // We only need minimal includes
//#include <windows.h>
//#define snprintf _snprintf // see comment in strutil.cc
//#elif defined(HAVE_PTHREAD)
#include <pthread.h>
//#else
//#error "No suitable threading library available."
//#endif
```
>此处参考了[protobuf 安装流程](http://blog.chinaunix.net/uid-28595538-id-5082366.html)
``` shell
$ sudo -E ./autogen.sh
$ sudo -E ./configure CXXFLAGS="$(pkg-config --cflags protobuf)" LIBS="$(pkg-config --libs protobuf)"
$ sudo -E make -j $(nproc)
$ sudo -E make install
$ sudo -E ldconfig
```

#### 编译成功验证
```
protoc --version
```
输出：libprotoc 3.9.0(或其他的版本号)
#### 第二种安装方法
由protobuf和grpc的安装的依赖关系，我们可以将它们视为一个组合，除了顺次编译外，还可以先编译grpc，再在third_party文件夹下的protobuf目录下安装protobuf，相关的编译方法网上能查到一些（可以搜protobuf+grpc编译），之前试了一下但编译成功率很低。

### 源码编译安装c-cares

```shell
$ git clone https://gitee.com/src-openeuler/c-ares.git
$ cd c-ares
$ git checkout openEuler-20.03-LTS-tag
$ tar -xzvf c-ares-1.15.0.tar.gz
$ cd c-ares-1.15.0
$ sudo -E autoreconf -if
$ sudo -E ./configure --enable-shared --disable-dependency-tracking
$ sudo -E make -j $(nproc)
$ sudo -E make install
$ sudo -E ldconfig
```
### 源码编译安装grpc

```shell
$ git clone https://gitee.com/src-openeuler/grpc.git
$ cd grpc
$ git checkout openEuler-20.03-LTS-tag
$ tar -xzvf grpc-1.22.0.tar.gz
$ cd grpc-1.22.0
```
修改源码：

*   在`include/grpcpp/impl/codegen/call_op_set.h` line 90添加

```shell
 /// Default assignment operator
  WriteOptions& operator=(const WriteOptions& other) = default;
```

*   将`src/core/lib/gpr/log_linux.cc`、`src/core/lib/gpr/log_posix.cc`、`src/core/lib/iomgr/ev_epollex_linux.cc`这几个文件中的
   `gettid()`改为`sys_gettid()`

>参考[protobuf+grpc源码编译安装过程](https://blog.csdn.net/Sindweller5530/article/details/104414856)

```shell
$ sudo -E make -j $(nproc)
$ sudo -E make install
$ sudo -E ldconfig
```
之后会遇到'cannot find -latomic'的问题,按[链接中的](https://www.cnblogs.com/mafy/p/13380332.html)处理即可:  


grpc测试用例
```
cd examples/cpp/helloworld/
make                 //编译
./greeter_server     //服务器
./greeter_client     //客户端（重新开一个服务器连接）
```
### 源码编译安装http-parser

```javascript
$ git clone https://gitee.com/src-openeuler/http-parser.git
$ cd http-parser
$ git checkout openEuler-20.03-LTS-tag
$ tar -xzvf http-parser-2.9.2.tar.gz
$ cd http-parser-2.9.2
$ sudo -E make -j CFLAGS="-Wno-error"
$ sudo -E make CFLAGS="-Wno-error" install
$ sudo -E ldconfig
```


### 源码编译安装libwebsockets
```shell
$ git clone https://gitee.com/src-openeuler/libwebsockets.git
$ cd libwebsockets
$ git checkout openEuler-20.03-LTS-tag
$ tar -xzvf libwebsockets-2.4.2.tar.gz
$ cd libwebsockets-2.4.2
$ patch -p1 -F1 -s < ../libwebsockets-fix-coredump.patch
$ mkdir build
$ cd build
$ sudo -E cmake -DLWS_WITH_SSL=0 -DLWS_MAX_SMP=32 -DCMAKE_BUILD_TYPE=Debug ../
$ sudo -E make -j $(nproc)
$ sudo -E make install
$ sudo -E ldconfig
```

### 源码编译安装lxc
```shell
$ git clone https://gitee.com/src-openeuler/lxc.git
$ cd lxc
$ tar -zxf lxc-4.0.3.tar.gz
$ ./apply-patches
$ cd lxc-4.0.3
$ sudo -E ./autogen.sh
$ sudo -E ./configure
$ sudo -E make -j
$ sudo -E make install
$ sudo -E ldconfig
```
在编译的过程中会遇到两个问题：
1. 关于`__NR_signalfd`
解决方案：[lxc的issue](https://github.com/lxc/lxc/pull/3501/files)
2. 再次遇到'cannot find -latomic'的问题
这次不能使用上次的方法，这次是缺少静态链接库，使用find命令搜到libatomic.a复制到/usr/lib下，编译通过。
### 源码编译安装lcr
```shell
$ git clone https://gitee.com/openeuler/lcr.git
$ cd lcr
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j
$ sudo -E make install
$ sudo -E ldconfig
```
### 源码编译安装clibcni
```shell
$ git clone https://gitee.com/openeuler/clibcni.git
$ cd clibcni
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j
$ sudo -E make install
$ sudo -E ldconfig
```
### 源码编译安装iSulad
```shell
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make
$ sudo -E make install
$ sudo -E ldconfig
```
## 内核编译及内核模块的编译
在完成上述工作之后，iSulad的启动还需要一个`overlay`的内核模块。虚拟机镜像默认没有提供，需要我们开启此模块和编译封装。
1. 下载与当前镜像系统一致的版本的内核源码（内核版本可以使用`uname -a`命令来查看）
```shell
git clone https://gitee.com/openeuler/kernel.git
git checkout 某一分支
```
2. 在内核源码的目录下，执行make menuconfig，在配置界面找到File systems ---> 在Overlay filesystem support前配置成[M]或[*]（单击空格键切换），之后保存并退出；
3. 使用make Image命令，在/内核源码路径/arch/riscv/boot/  下生成Image文件；
4. 下载内核封装工具opensbi:
```shell
git clone https://gitee.com/src-openeuler/opensbi.git
cd opensbi
unzip v0.6.zip
cd opensbi-0.6
make O=build-oe/qemu-virt PLATFORM=qemu/virt FW_PAYLOAD=y FW_PAYLOAD_PATH=/生成的Image路径/Image
```
这一步会生成elf文件，编译结束会提示elf文件所在位置。
5. 将elf文件拷贝至host,拷贝可以使用`scp`工具进行。将.qcow2文件、.elf文件、.sh文件放在同一路径下，修改run_oe1-rv64.sh中的kernel 参数处的elf文件名为新添加的elf文件名。
6. 执行sh run_oe1-rv64.sh  
### 参考链接:  
* https://arkingc.github.io/2018/09/05/2018-09-05-linux-kernel/
* https://gitee.com/src-openeuler/risc-v-kernel/blob/master/kernel.spec
* https://gitee.com/src-openeuler/opensbi/blob/master/opensbi.spec
