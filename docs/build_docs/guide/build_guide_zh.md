# 源码编译安装iSulad

源码编译安装的步骤复杂，不易操作，推荐您使用rpm包安装iSuald，具体请参照：[rpmbuild_guide](./build_guide_with_rpm_zh.md)。若您仍想源码编译安装iSulad，请参照以下步骤。

## 各发行版本上自动化源码编译安装iSulad

### openEuler的安装命令

在openEuler上可以直接通过编译依赖自动安装（其他rpm的发行版本也可以参考这种方式，但是存在部分包名不一致的情况），具体如下：  

```bash
 dnf builddep iSulad.spec
```

**注意**：
1. iSulad.spec直接用源码中的文件即可。
2. 由于isulad依赖于libcap-devel库的capability.h头文件，需要额外使用yum安装libcap-devel库。

之后源码编译安装isulad：

```bash
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```
**注意：** isula与isulad之间的通信默认使用grpc，若想要使用rest进行通信，可使用如下编译选项更换：

```c
cmake -DENABLE_GRPC=OFF ../
```

### Centos的安装命令

我们在代码仓中提供了在Centos7上自动化安装的脚本，您只需要执行这个脚本就可以自动编译安装iSulad以及其依赖的组件。

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs/build_docs/guide/script
$ sudo ./install_iSulad_on_Centos_7.sh
```

### Ubuntu的安装命令

我们同样在代码仓中提供了在Ubuntu上自动化安装的脚本，您只需要执行这个脚本就可以自动编译安装iSulad以及其依赖的组件。

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs/build_docs/guide/script
$ sudo chmod +x ./install_iSulad_on_Ubuntu_20_04_LTS.sh
$ sudo ./install_iSulad_on_Ubuntu_20_04_LTS.sh
```

**注意**：若需要保留各种依赖的源码，可将脚本中的`rm -rf $BUILD_DIR`注释。

## 逐步源码构建和安装iSulad

若您在使用自动化安装命令后，存在依赖组件在包管理中不存在或版本不满足要求，则可有选择的使用以下源码构建和安装所需依赖组件。

**注意：grpc-1.22不支持GCC 9+**。

同样，若您想要自己逐步源码编译安装iSulad，则可以按照以下步骤依次源码构建和安装基础依赖，之后再源码构建和安装关键依赖的特定版本。

### 源码构建和安装基础依赖

#### 设置ldconfig和pkgconfig的路径

编译安装的默认路径为`/usr/local/lib/`，因此需要把该路径添加到`PKG_CONFIG_PATH`和`LD_LIBRARY_PATH`，从而系统能找到我们编译安装的软件包和lib库。如果安装的路径为`/usr/lib/`，可以忽略这一步。

```bash
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
$ export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH
$ sudo -E echo "/usr/local/lib" >> /etc/ld.so.conf
```

**注意：** 若编译中断，再次进入系统进行源码编译之前，必须重新利用上述命令设置ldconfig和pkgconfig的路径。

#### 编译安装protobuf

```bash
$ git clone https://gitee.com/src-openeuler/protobuf.git
$ cd protobuf
$ git checkout openEuler-20.03-LTS-tag
$ tar -xzvf protobuf-all-3.9.0.tar.gz
$ cd protobuf-3.9.0
$ sudo -E ./autogen.sh
$ sudo -E ./configure
$ sudo -E make -j $(nproc)
$ sudo -E make install
$ sudo -E ldconfig
```

#### 编译安装c-ares

```bash
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

#### 编译安装grpc

```bash
$ git clone https://gitee.com/src-openeuler/grpc.git
$ cd grpc
$ git checkout openEuler-20.03-LTS-tag
$ tar -xzvf grpc-1.22.0.tar.gz
$ cd grpc-1.22.0
$ sudo -E make -j $(nproc)
$ sudo -E make install
$ sudo -E ldconfig
```

#### 编译安装libevent

```bash
$ git clone https://gitee.com/src-openeuler/libevent.git
$ cd libevent
$ git checkout -b openEuler-20.03-LTS-tag openEuler-20.03-LTS-tag
$ tar -xzvf libevent-2.1.11-stable.tar.gz
$ cd libevent-2.1.11-stable && ./autogen.sh && ./configure
$ sudo -E make -j $(nproc) 
$ sudo -E make install
$ sudo -E ldconfig
```

#### 编译安装libevhtp

```bash
$ git clone https://gitee.com/src-openeuler/libevhtp.git
$ cd libevhtp && git checkout -b openEuler-20.03-LTS-tag openEuler-20.03-LTS-tag
$ tar -xzvf libevhtp-1.2.16.tar.gz
$ cd libevhtp-1.2.16
$ patch -p1 -F1 -s < ../0001-support-dynamic-threads.patch
$ patch -p1 -F1 -s < ../0002-close-openssl.patch
$ rm -rf build && mkdir build && cd build
$ sudo -E cmake -D EVHTP_BUILD_SHARED=on -D EVHTP_DISABLE_SSL=on ../
$ sudo -E make -j $(nproc)
$ sudo -E make install
$ sudo -E ldconfig
```

#### 编译安装libwebsockets

```bash
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

### 源码构建和安装关键依赖的特定版本

最后，因为iSulad依赖一些特定版本的关键依赖组件，且各组件是通过函数接口调用，因此，**必须保证各关键依赖组件版本一致**。版本的一致包括以下四个方面：

- 分支一致：统一使用各组件的相同分支进行构建；
- releases一致：每个isulad的release都有适配的组件release，使用指定release的组件进行构建；
- 特定OS：若使用的为[openEuler](https://openeuler.org/zh/download/)的特定OS版本，则需要通过包管理工具获取各组件的`src.rpm`包的，从而获取源码进行构建；
- src-openeuler：若从[src-openeuler](https://gitee.com/src-openeuler)社区获取各组件，也需要保持组件都使用相同分支进行构建；

#### 编译安装lxc

```bash
$ git clone https://gitee.com/src-openeuler/lxc.git
$ cd lxc
$ ./apply-patches
$ cd lxc-4.0.3
$ sudo -E ./autogen.sh
$ sudo -E ./configure
$ sudo -E make -j $(nproc)
$ sudo -E make install
```

#### 编译安装lcr

```bash
$ git clone https://gitee.com/openeuler/lcr.git
$ cd lcr
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```

#### 编译安装clibcni

```bash
$ git clone https://gitee.com/openeuler/clibcni.git
$ cd clibcni
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```

#### 编译安装iSulad

```bash
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```
**注意：** isula与isulad之间的通信默认使用grpc，若想要使用rest进行通信，可使用如下编译选项更换：

```c
cmake -DENABLE_GRPC=OFF ../
```