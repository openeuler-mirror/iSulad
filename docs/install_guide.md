## Dependencies

This project depends on gRPC (need protobuf at least v3.1.0, gRPC at least v1.1.0) or REST (need libevent 2.1.8, libcurl at least 7.40, http-parser at least 2.6.2, local modified libevhtp), LCR. Other version are not tested, nor supported.

## Installation steps:

### Initialization

```sh
$ # for ubuntu
$ sudo apt-get install unzip libtool automake autoconf g++ cmake curl zlib1g-dev libcap-dev libseccomp-dev libyajl-dev libsqlite3-dev libwebsockets-dev
$ # for centos/RTOS
$ sudo yum install gcc-c++ autoconf libtool unzip automake cmake curl zlib-devel libcap-devel libseccomp-devel yajl-devel sqlite-devel libwebsockets-devel
```

### protobuf v3.5.0

Compile protobuf from source code:
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/third_party/open_source/userspace/protobuf
$ cd protobuf
$ git checkout -b next origin/next
$ tar -xf protobuf-3.5.0.tar.gz
$ cp googlemock-1.7.0.tar.gz googletest-1.7.0.tar.gz 0001-fix-build-on-s390x.patch protobuf-3.5.0
$ cd protobuf-3.5.0
$ tar -xf googlemock-1.7.0.tar.gz
$ tar -xf googletest-1.7.0.tar.gz
$ mv googlemock-release-1.7.0 gmock
$ tar -xf googletest-1.7.0.tar.gz -C gmock
$ mv gmock/googletest-release-1.7.0 gmock/gtest
$ patch -p1 < 0001-fix-build-on-s390x.patch
$ ./autogen.sh # Because of internal network issue, we need to change curl to allow insecure connections (curl -k)
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
$ tar xf grpc-1.17.1.tar.gz
$ cd grpc-1.17.1
$ git checkout -b next origin/next
$ patch -p1 < ../0001-Do-not-build-the-Ruby-plugin.patch
$ patch -p1 < ../0001-enforce-system-crypto-policies.patch
$ patch -p1 < ../0002-patch-from-15532.patch
$ patch -p1 < ../cxx-Arg-List-Too-Long.patch
$ make -j
$ sudo make install
$ sudo ldconfig
```

### clibcni

Compile clibcni from source code:
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/self_src/userspace/clibcni
$ cd clibcni
$ git checkout -b next_docker origin/next_docker
$ rm -rf build
$ mkdir build && cd build
$ cmake ..
$ make -j
$ sudo make install
$ sudo ldconfig
```
if enbale testcase
```sh
$ rm -rf build
$ mkdir build && cd build
$ cmake -DENABLE_TESTS=ON ..
$ make -j
$ sudo make install
$ sudo ldconfig
$ cd tests && ./cni_test
$ cd -
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
$ git clone http://dgggit09-rd.huawei.com/a/euleros/self_src/userspace/iSulad-kit
$ git clone http://dgggit09-rd.huawei.com/a/euleros/third_party/open_source/userspace/skopeo
$ cd skopeo
$ git checkout -b next_docker origin/next_docker
$ mkdir ./tmp
$ tar -zxf skopeo-e814f96.tar.gz --strip-components 1 -C ./tmp
$ cp -r ./tmp/vendor ../iSulad-kit/
$ cd ../iSulad-kit
$ git checkout -b next_docker origin/next_docker
$ patch -p1 -F1 -s < ../skopeo/backport-update-vendor-to-e96a9b0e1b9019f9.patch
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
$ make install
```

### LXC

Compile lxc from source code:
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/third_party/open_source/userspace/lxc
$ cd lxc
$ git checkout -b next_docker origin/next_docker
$ tar xf lxc-3.0.3.tar.gz
$ cd lxc-3.0.3
$ mv ../*.patch .
# official patch
$ for var in $(ls lxc-*.patch | sort -n)
  do
    if [[ "$var" =~ "CVE-2019-5736" ]]; then
      echo "ignoring CVE patch cause valgrind can not work"
      continue
    fi
    patch -p1 < ${var}
  done
  # self-developing patch
$ for var in $(ls huawei-*.patch | sort -n)
  do
    patch -p1 < ${var}
  done
$ ./autogen.sh
$ ./configure
$ make -j (If the GCC version on the system is greater than 7, please add CFLAGS="-Wno-error" option)
$ sudo make install
$ sudo ldconfig
```

### huawei securec library

Compile huawei securec library from source code:
```sh
$ git clone git@code-sh.huawei.com:containers/securec.git
$ cd securec
$ ./autogen.sh
$ ./configue
$ make -j $(nproc)
$ sudo make install
$ sudo ldconfig
```
### LCR

Note: If you encounter an error like "You must install [project] >= [version]" during executing "./configure",
please export the environment variable
```sh
$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

Compile lcr from source code:
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/self_src/userspace/lcr
$ cd lcr
$ git checkout -b next_docker origin/next_docker
$ mkdir -p build
$ cd build
$ cmake ../
$ make -j
$ sudo make install
$ sudo ldconfig
```

## Build LCRD
Note: If you encounter an error like "not found libcurl" during executing "./configure" on the ubuntu system,
please execute the following command:
```sh
$ sudo apt-get install libcurl4-gnutls-dev
```

In most cases, if we do not need to change the interface API(container.proto), just build the server and client like this:
```sh
$ git clone http://dgggit09-rd.huawei.com/a/euleros/self_src/userspace/iSulad
$ cd iSulad
$ git checkout -b next_docker origin/next_docker
$ rm -rf build
$ mkdir build && cd build
# To enable gRPC, configure lcrd by default
$ cmake ../
$ make -j (If the GCC version on the system is greater than 7, please add CFLAGS="-Wno-error" option)
$ sudo make install
$ sudo ldconfig
```

## Run

### Start daemon
Note: if you encounter an error like "error while loading shared libraries" when start the daemon ,
please execute the following command:
```sh
$ sudo echo "/usr/local/lib" >> /etc/ld.so.conf
```

You should have built and installed lcrd and lcrc. To run the daemon:
```sh
$ sudo lcrd  # run the lcrd server with default socket name and default log level and images manage function
```

### Download rootfs

To create a container, you should have downloaded rootfs to your platform like this:
```sh
$ mkdir $HOME/myrootfs
$ sudo lcr-pull --name ubuntu --rootfs $HOME/myrootfs --dist ubuntu -r xenial -a amd64
```
If lcrd started with the images manage function you can download images from registry (e.g., docker.io)

### Operations on containers:

```sh
$ sudo lcrc ps -a    # list containers
# create a container 'ubuntu1' with the directory
$ sudo lcrc create -n ubuntu1 --external-rootfs $HOME/myrootfs/ none
# or, you can create a container with OverlayFS
$ sudo mkdir $HOME/upperdir/   # create the upperdir for OverlayFS
$ sudo lcrc create -n 'ubuntu1' --external-rootfs overlayfs:$HOME/myrootfs:$HOME/upperdir none
$ sudo lcrc start ubuntu1   # start the container 'ubuntu1'
$ sudo lcrc kill ubuntu1    # kill the container 'ubuntu1'
```
