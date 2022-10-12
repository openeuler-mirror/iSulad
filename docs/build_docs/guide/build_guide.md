# Build and install iSulad from source

Due to the complicated steps of building and installation form source, it is recommended that you install iSuald through the rpm package. For details, please refer to: [rpmbuild_guide](./build_guide_with_rpm_zh.md). If you still want to build and install iSulad from source, please follow the steps below.

## Auto Build and install iSulad from source on different distribution

### install iSulad from source based on openEuler distribution

You can automatically install isulad on openEuler directly by compiling dependencies (other rpm distributions can also refer to this method, but some package names are inconsistent).

```bash
dnf builddep iSulad.spec
```

`tips`：iSulad.spec directly uses the files in the isulad source code.

Then, you should build and install iSulad:

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make
$ sudo -E make install
```
`tips`： The communication between isula and isulad uses grpc by default. If you want to use rest for communication, you can replace it with the following compilation options：

```c
cmake -DENABLE_GRPC=OFF ../
```

### install iSulad from source based on Centos distribution

We provided a script to auto install iSulad on centos7, you can just execute the script to install iSulad.

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs/build_docs/guide/script
$ sudo ./install_iSulad_on_Centos_7.sh
```

### install iSulad from source based on Ubuntu distribution

We also provided a script to auto install iSulad on Ubuntu20.04, you can just execute the script to install iSulad.

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs/build_docs/guide/script
$ sudo chmod +x ./install_iSulad_on_Ubuntu_20_04_LTS.sh
$ sudo ./install_iSulad_on_Ubuntu_20_04_LTS.sh
```

`tips`:  If you want to keep the source of all dependencies, you can comment `rm -rf $BUILD_DIR` in the script.

## Build and install iSulad from source by yourself

After executing the automated installation command, if there are dependencies  that do not exist in the package management or the versions do not meet the requirements, you can optionally build them from source.

**Note: grpc-1.22 can not support GCC 9+**.

Similarly, if you want to build and install iSulad from source step by step, you can follow the steps below to build and install basic dependencies, and then build and install specific versions of key dependencies.

### build and install base dependencies from source 

#### set ldconfig and pkgconfig

The default installation path is `/usr/local/lib/`, which needs to be added to `PKG_CONFIG_PATH` and `LD_LIBRARY_PATH`, so that the system can find the packages and lib libraries. If the installed path is `/usr/lib/`, you can ignore this step.

```bash
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
$ export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH
$ sudo -E echo "/usr/local/lib" >> /etc/ld.so.conf
```

**Note:** If the build is interrupted, you must re-execute the above commands to set the paths of ldconfig and pkgconfig before building the source again.

#### build and install protobuf

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

#### build and install c-ares

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

#### build and install grpc

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

#### build and install libevent

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

#### build and install libevhtp

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

#### build and install http-parser

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

#### build and install libwebsockets

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

### Build and install specific versions of critical dependencies from source 

Finally, because iSulad depends on some specific versions of key dependencies, and each dependency is called through a functional interface, **you must ensure that the versions of all key dependencies are consistent**.

The consistency of the version includes the following four aspects:

- Branch consistency: build and install the same branch of each dependency;
- Consistent releases: Since each isulad release has an adapted dependency release, you need to build and install the dependencies of the specified release;
- Specific OS: If you use a specific OS version of [openEuler](https://openeuler.org/zh/download/), you need to obtain the `src.rpm` package of each dependency through the package management tool to obtain the source to build and install;
- Src-openeuler: If the dependencies are obtained from the [src-openeuler](https://gitee.com/src-openeuler) community, it is also necessary to keep the dependencies built with the same branch;

#### build and install lxc

```bash
$ git clone https://gitee.com/src-openeuler/lxc.git
$ cd lxc
$ tar -zxf lxc-4.0.3.tar.gz
$ ./apply-patches
$ cd lxc-4.0.3
$ sudo -E ./autogen.sh
$ sudo -E ./configure
$ sudo -E make -j
$ sudo -E make install
```

#### build and install lcr

```bash
$ git clone https://gitee.com/openeuler/lcr.git
$ cd lcr
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j
$ sudo -E make install
```

#### build and install clibcni

```bash
$ git clone https://gitee.com/openeuler/clibcni.git
$ cd clibcni
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j
$ sudo -E make install
```

#### build and install iSulad

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make
$ sudo -E make install
```
**Tips：** The communication between isula and isulad uses grpc by default. If you want to use rest for communication, you can replace it with the following compilation options：

```c
cmake -DENABLE_GRPC=OFF ../
```