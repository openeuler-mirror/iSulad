## Dependencies

This project depends on gRPC (need protobuf at least v3.1.0, gRPC at least v1.1.0) or REST (need libevent 2.1.8, libcurl at least 7.40, http-parser at least 2.6.2, local modified libevhtp), LCR. Other version are not tested, nor supported.

## Installation steps:

### Initialization

```sh
$ sudo yum install -y go gcc gcc-c++ autoconf libtool unzip automake cmake curl zlib-devel libcap-devel libseccomp-devel \
$ yajl-devel sqlite-devel libwebsockets-devel openssl-devel c-ares-devel zlib-devel python3-devel python3-setuptools libsecurec-devel
$ sudo sh -c "echo /usr/local/lib >> /etc/ld.so.conf"
$ sudo sh -c 'echo "export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH" >> /etc/bashrc'
```

### protobuf v3.5.0

Compile protobuf from source code:
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/third_party/open_source/userspace/protobuf
$ cd protobuf
$ git checkout -b open origin/next_openeuler
$ tar -xf v3.5.0.tar.gz
$ cp googlemock-1.7.0.tar.gz googletest-1.7.0.tar.gz 0001-fix-build-on-s390x.patch protobuf-3.5.0
$ cd protobuf-3.5.0
$ tar -xf googlemock-1.7.0.tar.gz
$ tar -xf googletest-1.7.0.tar.gz
$ mv googlemock-release-1.7.0 gmock
$ tar -xf googletest-1.7.0.tar.gz -C gmock
$ mv gmock/googletest-release-1.7.0 gmock/gtest
$ patch -p1 < 0001-fix-build-on-s390x.patch
$ ./autogen.sh
$ ./configure
$ make -j
$ sudo make install
$ sudo ldconfig
```

### gRPC v1.17.1

Compile the gRPC C Core library
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/third_party/open_source/userspace/grpc
$ cd grpc
$ git checkout -b open origin/next_openeuler
$ tar xf v1.17.1.tar.gz
$ cd grpc-1.17.1
$ patch -p1 < ../0001-enforce-system-crypto-policies.patch
$ patch -p1 < ../0002-patch-from-15532.patch
$ patch -p1 < ../0003-Do-not-build-the-Ruby-plugin.patch
$ patch -p1 < ../0001-cxx-Arg-List-Too-Long.patch
$ make -j
$ sudo make install
$ sudo ldconfig
```

### clibcni

Compile clibcni from source code:
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/self_src/userspace/clibcni
$ cd clibcni
$ git checkout -b open origin/next_openeuler
$ rm -rf build
$ mkdir build && cd build
$ cmake ..
$ make -j
$ sudo make install
$ sudo ldconfig
```

### containernetworking plugins

Compile containernetworking plugins from source code:
```sh
$ git clone http://code-sh.rnd.huawei.com/containers/plugins/plugins.git
$ cd plugins
$ git checkout critest
$ ./build.sh
$ mkdir -p /opt/cni/bin
$ cp bin/* /opt/cni/bin/
```

### iSulad-kit

Compile iSulad-kit from source code:
```sh
$ yum install -y gpgme-devel
$ git clone http://dgggit09-rd.huawei.com/a/euleros/self_src/userspace/iSulad-kit
$ cd iSulad-kit
$ git checkout -b open origin/next_openeuler
# apply the patchs
$ cp ./patch/* ./
$ cat series-patch.conf | while read line
  do
    if [[ $line == '' || $line =~ ^\s*# ]]; then
      continue
    fi
    patch -p1 -F1 -s < $line
  done
$ make -j
$ sudo make install
```

### LXC

Compile lxc from source code:
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/third_party/open_source/userspace/lxc
$ cd lxc
$ git checkout -b open origin/next_openeuler
$ tar xf lxc-3.0.3.tar.gz
$ cd lxc-3.0.3
$ mv ../*.patch .
# official patch
$ for var in $(ls lxc-*.patch | sort -n)
  do
    patch -p1 < ${var}
  done
  # self-developing patch
$ for var in $(ls *.patch | grep -v "^lxc-" | sort -n)
  do
    patch -p1 < ${var}
  done
$ ./autogen.sh
$ ./configure
$ make -j # If the GCC version on the system is greater than 7, please add CFLAGS="-Wno-error" option
$ sudo make install
$ sudo ldconfig
```

### LCR

Compile lcr from source code:
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/self_src/userspace/lcr
$ cd lcr
$ git checkout -b open origin/next_openeuler
$ mkdir -p build
$ cd build
$ cmake ../
$ make -j
$ sudo make install
$ sudo ldconfig
```

## Build iSulad

```sh
$ yum install -y libcurl-devel http-parser-devel systemd-devel libevent-devel libevhtp-devel
$ git clone http://dgggit09-rd.huawei.com/a/euleros/self_src/userspace/iSulad
$ cd iSulad
$ git checkout -b open origin/next_openeuler
$ mkdir -p build && cd build
# To enable gRPC, configure iSulad by default
$ cmake ../
$ make -j # If the GCC version on the system is greater than 7, please add CFLAGS="-Wno-error" option
$ sudo make install
$ sudo ldconfig
```

## Run

### Start daemon

You should have built and installed lcrd and lcrc. To run the daemon:
```sh
$ sudo lcrd  # run the iSulad server with default socket name and default log level and images manage function
```

### Operations on containers:

```sh
$ sudo lcrc ps -a    # list containers
# create a container 'test' with image busybox
$ sudo lcrc create -t -n test busybox
$ sudo lcrc start test   # start the container 'test'
$ sudo lcrc kill test    # kill the container 'test'
$ sudo lcrc rm test    # remove the container 'test'
```
