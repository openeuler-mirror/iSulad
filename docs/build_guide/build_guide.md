# Build iSulad from source

If you intend to contribute on iSulad. Thanks for your effort. Every contribution is very appreciated for us.

## Install basic dependencies on different distribution

These dependencies are required for build:

### install basic dependencies based on Centos distribution

We provided a script to auto install iSulad on centos7, you can just execute the script to install iSulad.

```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs
$ sudo ./install_iSulad_on_Centos_7.sh
```

### install basic dependencies based on Ubuntu distribution
```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad/docs
$ sudo ./docs/install_iSulad_on_Ubuntu_20_04_LTS.sh
```

## Build and install other dependencies from source
These dependencies may not be provided by your package manager. So you need to build them from source.

Please use the protobuf and grpc came with your distribution, if not exists then need to build them from source.

Note: grpc-1.22 can not support GCC 9+.

### set ldconfig and pkgconfig
```bash
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
$ export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH
$ sudo -E echo "/usr/local/lib" >> /etc/ld.so.conf
```
### build and install protobuf
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

### build and install c-ares
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

### build and install grpc
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

### build and install libevent

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

### build and install libevhtp

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

### build and install http-parser
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

### build and install libwebsockets
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

## Build and install specific versions dependencies from source
iSulad depend on some specific versions dependencies.

### build and install lxc
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

### build and install lcr
```bash
$ git clone https://gitee.com/openeuler/lcr.git
$ cd lcr
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j
$ sudo -E make install
```

### build and install clibcni
```bash
$ git clone https://gitee.com/openeuler/clibcni.git
$ cd clibcni
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make -j
$ sudo -E make install
```

### build and install iSulad
```sh
$ git clone https://gitee.com/openeuler/iSulad.git
$ cd iSulad
$ mkdir build
$ cd build
$ sudo -E cmake ..
$ sudo -E make
$ sudo -E make install
```
