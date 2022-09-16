# Make rpm package


## 1. Preparation

First install the rpmbuild tool and initialize the rpmbuild working directory:

```shell
yum install -y rpm-build
rpmbuild -ba isulad.spec
```

The second command will exit with an error, but this command will still create the rpmbuild directory in the user's default working directory.

In the rpmbuild working directory, you will find the following subdirectories:

```shell
$ ls ~/rpmbuild
BUILD  BUILDROOT  RPMS	SOURCES  SPECS	SRPMS
```

**tips**:

- `SOURCES` stores the source code
- `SPECS` stores the SPEC files used for the build
- `RPMS` stores rpm packages.

## 2. Install base dependencies

```shell
dnf install -y patch automake autoconf libtool cmake make libcap libcap-devel libselinux libselinux-devel libseccomp libseccomp-devel git libcgroup tar python3 python3-pip  libcurl-devel zlib-devel glibc-headers openssl-devel gcc gcc-c++ systemd-devel systemd-libs golang libtar && \
dnf --enablerepo=powertools install -y yajl-devel device-mapper-devel http-parser-devel && \
dnf install -y epel-release && \
dnf --enablerepo=powertools install libuv-devel &&\
dnf install libwebsockets-devel
```

## 3. Build lxc rpm package

### 3.1 install lxc dependencies

```shell
 dnf --enablerepo=powertools install -y docbook2X doxygen && \
 dnf install -y bash-completion chrpath rsync
```

### 3.2 prepare the lxc build environment

First download the lxc source code:

```shell
git clone https://gitee.com/src-openeuler/lxc.git
```

Put the source code, patch, and spec into the rpmbuild working directory:

```shell
export RPM=~/rpmbuild
cd lxc
cp *.patch *.tar.gz $RPM/SOURCES/ && \
cp *.spec $RPM/SPECS/
```

### 3.3 build

```shell
cd ~/rpmbuild/SPECS
rpmbuild -ba lxc.spec
```

### 3.4 install

After the build is successful, the rpm package will be placed in the RPM directory. You can find the corresponding rpm package and install it with the `rpm -Uvh`.

```shell
cd ~/rpmbuild/RPMS/x86_64
rpm -Uvh lxc-libs-4.0.3-2022080901.x86_64.rpm
rpm -Uvh lxc-4.0.3-2022080901.x86_64.rpm
rpm -Uvh lxc-devel-4.0.3-2022080901.x86_64.rpm
```

## 4. Build lcr rpm package

### 4.1 install lcr dependencies

```shell
dnf --enablerepo=powertools install -y gtest-devel
```

**Note**： lxc must be installed before installing lcr.

### 4.2 prepare the lcr build environment

First download the lcr source code:

```shell
git clone https://gitee.com/openeuler/lcr
```

Then package the source code:

```shell
export RPM=~/rpmbuild
cd lcr
tar -zcvf lcr-2.0.tar.gz *
```

Finally put the required source code, patch, and spec into the rpmbuild working directory:

```shell
cp lcr-2.0.tar.gz $RPM/SOURCES/
cp *.spec $RPM/SPECS/
```

### 4.3 build

```shell
cd ~/rpmbuild/SPECS
rpmbuild -ba lcr.spec
```

### 4.4 install

```sh
rpm -Uvh lcr-2.1.0-2.x86_64.rpm
rpm -Uvh lcr-devel-2.1.0-2.x86_64.rpm
```

## 5. Build clibcni rpm package

### 5.1 install clibcni dependencies 

```shell
dnf --enablerepo=powertools install -y gmock-devel
```

### 5.2 prepare the clibcni build environment

First download the clibcni  source code:

```shell
git clone https://gitee.com/openeuler/clibcni
```

Then package the source code:

```shell
cd clicni
tar -zcvf clibcni-2.0.tar.gz *
```

 Finally put the required source code, patch, and spec into the rpmbuild working directory:

```shell
cp clibcni-2.0.tar.gz $RPM/SOURCES/
cp *.spec $RPM/SPECS/
```

### 5.3 build

```shell
cd ~/rpmbuild/SPECS
rpmbuild -ba clibcni.spec
```

### 5.4 install

After the build is successful, the rpm package will be placed in the RPM directory . You can find the corresponding rpm package and install it with the `rpm -Uvh`.

## 6. Build protobuf rpm package

### 6.1 install protobuf dependencies 

```shell
yum install -y emacs.x86_64
```

### 6.2 prepare protobuf build environment

First download the protobuf  source code, Then package the source code, Finally put the required source code, patch, and spec into the rpmbuild working directory:

```shell
git clone https://gitee.com/src-openeuler/protobuf 
cd protobuf
git checkout openEuler-20.03-LTS
cp *.tar.gz *.el *.patch $RPM/SOURCES/ && cp *.spec $RPM/SPECS/
```

Since isulad does not need to build protobuf for java and python, you can modify the first 5 lines of the spec file to avoid installing related dependencies:

```shell
cd ~/rpmbuild/SPECS
vim protobuf.spec
%bcond_with python
%bcond_with java
```

### 6.3 build

```shell
rpmbuild -ba protobuf.spec
```

### 6.4 install

```sh
rpm -Uvh protobuf-3.14.0-4.x86_64.rpm
dnf install -y emacs-26.1-7.el8.x86_64
rpm -Uvh protobuf-compiler-3.14.0-4.x86_64.rpm
rpm -Uvh protobuf-devel-3.14.0-4.x86_64.rpm
```

## 7. Build grpc rpm package

### 7.1 install grpc dependencies： 

```shell
yum install -y emacs.x86_64 openssl-devel.x86_64
dnf --enablerepo=powertools install gflags-devel python3-Cython python3-devel
dnf install -y abseil-cpp-devel gperftools-devel re2-devel
```

### 7.2 prepare grpc build environment

```shell
git clone https://gitee.com/src-openeuler/grpc
cd grpc
git checkout openEuler-20.03-LTS
cp *.tar.gz $RPM/SOURCES/ && cp *.spec $RPM/SPECS/
```

### 7.3 build

```shell
rpmbuild -ba grpc.spec
```

### 7.4 install

```sh
dnf install -y epel-release.noarch c-ares-1.13.0-5.el8.x86_64 gperftools-libs-2.7-9.el8.x86_64
dnf --enablerepo=powertools install gflags-devel
rpm -Uvh grpc-1.31.0-1.x86_64.rpm
dnf install -y openssl-devel.x86_64
rpm -Uvh grpc-devel-1.31.0-1.x86_64.rpm
```

## 8. build libarchive rpm package

### 8.1 install libarchive dependencies

```shell
dnf install -y bzip2-devel e2fsprogs-devel libattr-devel libxml2-devel lz4-devel lzo-devel sharutils libacl-devel
dnf --enablerepo=powertools install sharutils
```

### 8.2 prepare libarchive build environment

```shell
git clone https://gitee.com/src-openeuler/libarchive
cd libarchive
git checkout openEuler-20.03-LTS
cp *.tar.gz *.patch $RPM/SOURCES/ && cp *.spec $RPM/SPECS/
```

### 8.3 build

```shell
rpmbuild -ba libarchive.spec
```

### 8.4 install

```shell
rpm -Uvh libarchive-3.4.3-4.x86_64.rpm
rpm -Uvh libarchive-devel-3.4.3-4.x86_64.rpm
```

## 9. Build iSulad rpm package

### 9.1 install iSulad dependencies

```shell
dnf --enablerepo=powertools install http-parser-devel
dnf install -y sqlite-devel
```

### 9.2 prepare iSulad build environment

```shell
git clone https://gitee.com/openeuler/iSulad
cd iSulad/
tar -zcvf iSulad-2.1.tar.gz *
```

```shell
cp iSulad-2.1.tar.gz $RPM/SOURCES/
cp *.spec $RPM/SPECS/
```

### 9.3 build

```shell
rpmbuild -ba iSulad.spec
```

### 9.4 install

First, you should install libwebsockets:

```shell
dnf install -y epel-release
dnf --enablerepo=powertools install libuv-devel
dnf install libwebsockets-devel
```

then, you can install iSulad

```shell
dnf --enablerepo=powertools install http-parser-devel
dnf install -y sqlite-devel.x86_64
rpm -Uvh iSulad-2.1.0-1.x86_64.rpm
```