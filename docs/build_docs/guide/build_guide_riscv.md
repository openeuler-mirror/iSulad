# Build guide on RISC-V openEuler


---

## Build a RISC-V virtual environment

>We can build a RISC-V virtual environment by using the QEMU virtual machine on the host. Specifically, you should use any Linux distribution as the host to install the QEMU virtual machine, then start the RISC-V openEuler image in the virtual machine, and finally install iSulad in the virtual machine image.

### 1. Install the virtual machine

The first is to install QEMU on the host, open a terminal, and run the following commands in turn:

```shell
wget https://download.qemu.org/qemu-5.1.0.tar.xz
tar xvJf qemu-5.1.0.tar.xz
cd qemu-5.1.0
./configure --target-list=riscv64-softmmu
make 
make install
```

### 2. Startup file preparation

After installing the QEMU that supports RISC-V, you can use it to start the image of the virtual machine. For the download and installation of the image, please refer to [Getting and Running the OpenEuler RISC-V Ported Version](https://gitee.com/openeuler /RISC-V/blob/master/documents/Installing.md). 

The following files are required to start the QEMU virtual machine:

- [oe-rv-rv64g-30G.qcow2](https://isrc.iscas.ac.cn/mirror/openeuler-sig-riscv/images/oe-rv-rv64g-30G.qcow2)

- [fw_payload_oe.elf](https://isrc.iscas.ac.cn/mirror/openeuler-sig-riscv/images/fw_payload_oe.elf)

- run_oe1_rv64.sh(optional)


You can create `run_oe1_rv64.sh` as follows:


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

There are some parameter settings, you can view the parameter description of QEMU and adjust it according to the local computer configuration.

### 3. Start the virtual machine

There are two ways to start a virtual machine:

1. Enter the contents of the shell file directly in the terminal.
2. If the shell file is created, just type `sh run_oe1_rv64.sh` in the terminal.

The default login username/password is: root/openEuler12#$

## Build and install iSulad from source

> First use yum to install the required dependent packages, and then refer to [build_guide](https://gitee.com/openeuler/iSulad/blob/master/docs/build_docs/guide/build_guide.md)'s `Build and install iSulad from source by yourself `. The errors that may occur during the process and their solutions are given below.

### Dependent package installation

Use the yum to install rpm packages. If you have just used `oe-rv-rv64g-30G.qcow2` without the yum provided, you can use the following command to install yum:

```shell
wget https://isrc.iscas.ac.cn/mirror/openeuler-sig-riscv/oe-RISCV-repo/noarch/yum-4.2.15-8.noarch.rpm --no-check-certificate
rpm -ivh yum-4.2.15-8.noarch.rpm
```

After that, use the yum to install the required packages:

```shell
sudo yum --enablerepo='*' install -y automake autoconf libtool cmake make libcap libcap-devel libselinux libselinux-devel libseccomp libseccomp-devel yajl-devel git libcgroup tar python3 python3-pip device-mapper-devel libarchive libarchive-devel libcurl-devel zlib-devel glibc-headers openssl-devel gcc gcc-c++ systemd-devel systemd-libs libtar libtar-devel vim
```

If you want to modify the yum repository, you can change the `oe-rv.repo` file under `/etc/yum.repos.d/`. Usually set the yum repository as [Index of /oe-RISCV-repo/](https://isrc.iscas.ac.cn/mirror/openeuler-sig-riscv/oe-RISCV-repo/).

### Possible errors and their solutions

#### `Clock skew detected`

Adjust the virtual machine time to local time. The format of the time adjustment command is as follows: date -s 2020-09-28.

#### build and install protobuf

Different from build_guide, you need to choose to install in either of the following two ways, so that the subsequent grpc can be build smoothly:

##### method one

First run the following command:

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

> This process refers to [stack overflow](https://stackoverflow.com/questions/53586540/c-terminate-called-after-throwing-an-instance-of-stdsystem-error). if you follow the build_guide, ` 'std::system_error'` appears when building grpc.

Before installing, make some modifications in the `src/google/protobuf/stubs/common.cc` :

```sh
vi src/google/protobuf/stubs/common.cc
```

In this file, comment out all the code related to _WIN32, as follows:

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

>Refer to [protobuf installation process](http://blog.chinaunix.net/uid-28595538-id-5082366.html)

``` shell
$ sudo -E ./autogen.sh
$ sudo -E ./configure CXXFLAGS="$(pkg-config --cflags protobuf)" LIBS="$(pkg-config --libs protobuf)"
$ sudo -E make -j $(nproc)
$ sudo -E make install
$ sudo -E ldconfig
```

Finally, verify that the installation was successful.

```
protoc --version
```

Output: libprotoc 3.9.0 (or other version)

##### method two

Due to the dependencies between protobuf and grpc installation, you can regard them as a combination, install grpc first, and then install protobuf in the protobuf directory under the third_party folder. 

The related compilation method can be searched for `protobuf+grpc compilation`. But the success rate of combined installation is very low.

#### build and install grpc

```shell
$ git clone https://gitee.com/src-openeuler/grpc.git
$ cd grpc
$ git checkout openEuler-20.03-LTS-tag
$ tar -xzvf grpc-1.22.0.tar.gz
$ cd grpc-1.22.0
```

Modify the source:

*   Add the followings in `include/grpcpp/impl/codegen/call_op_set.h` line 90

```shell
 /// Default assignment operator
  WriteOptions& operator=(const WriteOptions& other) = default;
```

*   Change `gettid` in `src/core/lib/gpr/log_linux.cc`, `src/core/lib/gpr/log_posix.cc`, `src/core/lib/iomgr/ev_epollex_linux.cc` () to `sys_gettid()`

>Refer to [protobuf+grpc build and install form source](https://blog.csdn.net/Sindweller5530/article/details/104414856)

```shell
$ sudo -E make -j $(nproc)
$ sudo -E make install
$ sudo -E ldconfig
```

After that, you will encounter the problem of `cannot find -latomic`, and you can handle it according to the [link](https://www.cnblogs.com/mafy/p/13380332.html):


grpc test case:

```bash
cd examples/cpp/helloworld/
make                 //build
./greeter_server     //server
./greeter_client     //client（reopen a server connection）
```

#### problems with installing lxc

There are two problems encountered in the process of building lxc:

- About the `__NR_signalfd` 

  solution: [lxc's issue](https://github.com/lxc/lxc/pull/3501/files)

- The error of `cannot find -latomic` is reported again
  This error is caused by the lack of a static link library. Use the find command to search for libatomic.a and copy it to /usr/lib.

## Building the kernel module

The startup of iSulad also requires an `overlay` kernel module. Since the virtual machine image does not provide `overlay` by default, you need to enable this module and build the package.

1. Download the kernel source code of the version consistent with the current mirror system (the kernel version can be viewed using the `uname -a` command)

```shell
git clone https://gitee.com/openeuler/kernel.git
git checkout 某一分支
```

2. In the directory of the kernel source code, execute `make menuconfig`, find `File systems`  ---> Configure it as [M] or [*] before Overlay filesystem support (click the space bar to switch), then save and exit;
3. Use `make Image` to generate an Image file under ./arch/riscv/boot/;
4. Download the kernel packaging tool `opensbi`:

```shell
git clone https://gitee.com/src-openeuler/opensbi.git
cd opensbi
unzip v0.6.zip
cd opensbi-0.6
make O=build-oe/qemu-virt PLATFORM=qemu/virt FW_PAYLOAD=y FW_PAYLOAD_PATH=/Generated Image path/Image
```

This step will generate the elf file, and the location of the elf file will be prompted at the end of the build.

5. First use `scp` to copy the elf file to the host. Then put the .qcow2 file, .elf file, and .sh file in the same path. Finally modify the elf file name at the kernel parameter in `run_oe1-rv64.sh` to the  name of generated elf file.
6. Execute sh `run_oe1-rv64.sh`

## Reference

* https://arkingc.github.io/2018/09/05/2018-09-05-linux-kernel/
* https://gitee.com/src-openeuler/risc-v-kernel/blob/master/kernel.spec
* https://gitee.com/src-openeuler/opensbi/blob/master/opensbi.spec