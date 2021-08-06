# 源码编译iSulad

我们感谢为iSulad做的任何贡献。

## 各发行版本的基本依赖安装

这些依赖是编译依赖的基础组件：

### openEuler的安装命令

openEuler可以直接通过编译依赖自动安装的方式（其他rpm的发行版本也可以参考，但是存在部分包名不一致的情况），具体如下：

```bash
dnf builddep iSulad.spec
```

注：iSulad.spec直接用源码中的文件即可。

### Centos的安装命令

我们在代码仓中提供了在Centos7上自动化安装的脚本，您只需要执行这个脚本就可以自动编译安装iSulad以及其依赖的组件。

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs
$ sudo ./install_iSulad_on_Centos_7.sh
```

### Ubuntu的安装命令
```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs
$ sudo chmod +x ./install_iSulad_on_Ubuntu_20_04_LTS.sh
$ sudo ./install_iSulad_on_Ubuntu_20_04_LTS.sh
```

## 从源码构建和安装关键依赖
下面的依赖组件，你的包管理中可能不存在，或者版本不满足要求。因此，需要从源码编译安装。protobuf和grpc建议直接通过包管理安装，除非没有或者版本太老。

***注意：grpc-1.22不支持GCC 9+。***

### 设置ldconfig和pkgconfig的路径

编译安装的默认路径为`/usr/local/lib/`，因此需要把该路径添加到`PKG_CONFIG_PATH`和`LD_LIBRARY_PATH`，从而系统能找到我们编译安装的软件包和lib库。如果安装的`/usr/lib/`，可以忽略这一步。

```bash
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
$ export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH
$ sudo -E echo "/usr/local/lib" >> /etc/ld.so.conf
```
### 编译安装protobuf
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

### 编译安装c-ares
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

### 编译安装grpc
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

### 编译安装http-parser
```bash
$ git clone https://gitee.com/src-openeuler/http-parser.git
$ cd http-parser
$ git checkout openEuler-20.03-LTS-tag
$ tar -xzvf http-parser-2.9.2.tar.gz
$ cd http-parser-2.9.2
$ sudo -E make -j CFLAGS="-Wno-error"
$ sudo -E make CFLAGS="-Wno-error" install
$ sudo -E ldconfig
```

### 编译安装libwebsockets
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

## 编译安装特定依赖版本
iSulad依赖一些特定版本的组件，由于各组件是通过函数接口使用，因此，**必须保证各组件版本一致**。例如：

- 统一使用各组件的master分支的代码进行构建；
- 后续的releases版本会增加依赖的组件的版本号；
- 也统一可以从[openEuler](https://openeuler.org/zh/download/)的特定OS版本，通过包管理工具获取各组件的`src.rpm`包的方式获取源码；
- 也可以到[src-openeuler](https://gitee.com/src-openeuler)社区获取各组件相同分支的代码；

### 编译安装lxc
```bash
$ git clone https://gitee.com/src-openeuler/lxc.git
$ cd lxc
$ tar -zxf lxc-4.0.3.tar.gz
$ ./apply-patches
$ cd lxc-4.0.3
$ sudo -E ./autogen.sh
$ sudo -E ./configure
$ sudo -E make -j $(nproc)
$ sudo -E make install
```

### 编译安装lcr
```bash
$ git clone https://gitee.com/openeuler/lcr.git
$ cd lcr
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```

### 编译安装clibcni
```bash
$ git clone https://gitee.com/openeuler/clibcni.git
$ cd clibcni
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```

### 编译安装iSulad
```bash
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j $(nproc)
$ sudo -E make install
```
