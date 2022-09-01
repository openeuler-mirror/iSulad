# Install iSulad with rpm package
You can also try to install iSulad using rpm with the rpm packages. The rpm packages can be built by referencing [rpmbuild_guid.md](rpmbuild_guide_zh.md).

## Build Steps on Centos 8

### Install lxc
```shell
dnf install -y yajl-2.1.0-10.el8.x86_64 rsync-3.1.3-12.el8.x86_64
rpm -Uvh lxc-libs-4.0.3-2022072501.x86_64.rpm
rpm -Uvh lxc-4.0.3-2022072501.x86_64.rpm
```

### Install lcr
```shell
dnf instal -y pkgconf-pkg-config-1.4.2-1.el8.x86_64
rpm -Uvh lcr-2.1.0-2.x86_64.rpm
rpm -Uvh lcr-devel-2.1.0-2.x86_64.rpm
```

### Install protobuf
```shell
rpm -Uvh protobuf-3.14.0-4.x86_64.rpm
dnf install -y emacs-26.1-7.el8.x86_64
rpm -Uvh protobuf-compiler-3.14.0-4.x86_64.rpm
rpm -Uvh protobuf-devel-3.14.0-4.x86_64.rpm
```

### Install grpc
```shell
dnf install -y epel-release.noarch c-ares-1.13.0-5.el8.x86_64 gperftools-libs-2.7-9.el8.x86_64
dnf --enablerepo=powertools install gflags-devel
rpm -Uvh grpc-1.31.0-1.x86_64.rpm
dnf install -y openssl-devel.x86_64
rpm -Uvh grpc-devel-1.31.0-1.x86_64.rpm
```

### Install libarchive
```shell
rpm -Uvh libarchive-3.4.3-4.x86_64.rpm
rpm -Uvh libarchive-devel-3.4.3-4.x86_64.rpm
```

### Install libwebsockets
```shell
dnf install -y epel-release
dnf --enablerepo=powertools install libuv-devel
dnf install libwebsockets-devel
```

### Install iSulad
```shell
dnf --enablerepo=powertools install http-parser-devel
dnf install -y sqlite-devel.x86_64
rpm -Uvh iSulad-2.1.0-1.x86_64.rpm
```