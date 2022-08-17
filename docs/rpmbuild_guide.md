# 制作iSulad依赖组件和iSulad的rpm包


## 1. 准备工作
首先要安装rpmbuild工具和初始化rpmbuild的工作目录：
```shell
yum install -y rpm-build
rpmbuild -ba isulad.spec
```
后面那个命令会出错退出， 但是这条命令只是为了创建rpmbuild的工作目录， 执行后可以发现在当前用户默认工作目录下出现了rpmbuild目录。

进入rpmbuild工作目录， 可以发现有如下子目录：
```shell
$ ls ~/rpmbuild
BUILD  BUILDROOT  RPMS	SOURCES  SPECS	SRPMS
```
源码放在`SOURCES`目录下， 用于构建的SPEC文件放在`SPECS`下， 构建完成的包会3放在`RPMS`下。

## 2. 安装基础依赖
```shell
dnf install -y patch automake autoconf libtool cmake make libcap libcap-devel libselinux libselinux-devel libseccomp libseccomp-devel git libcgroup tar python3 python3-pip  libcurl-devel zlib-devel glibc-headers openssl-devel gcc gcc-c++ systemd-devel systemd-libs golang libtar && \
dnf --enablerepo=powertools install -y yajl-devel device-mapper-devel http-parser-devel && \
dnf install -y epel-release && \
dnf --enablerepo=powertools install libuv-devel &&\
dnf install libwebsockets-devel
```
使用这些命令用centos上的包管理器安装一些基础依赖。

## 3. 构建lxc rpm包

### 3.1 安装lxc的依赖：
```shell
 dnf --enablerepo=powertools install -y docbook2X doxygen && \
 dnf install -y bash-completion chrpath rsync
```

### 3.2 准备lxc构建环境
先下载lxc源码
```shell
git clone https://gitee.com/src-openeuler/lxc.git
```

把所需要的源码，patch， spec放到rpmbuild工作目录：
```shell
export RPM=~/rpmbuild
cd lxc
cp *.patch *.tar.gz $RPM/SOURCES/ && \
cp *.spec $RPM/SPECS/
```

### 3.3 进行构建
```shell
cd ~/rpmbuild/SPECS
rpmbuild -ba lxc.spec
```

### 3.4 安装
构建成功后， rpm包会放在rpmbuild工作目录中的RPM目录中， 可以找到对应的lxc rpm包然后用`rpm -Uvh`命令安装

```shell
cd ~/rpmbuild/RPMS/x86_64
rpm -Uvh lxc-libs-4.0.3-2022080901.x86_64.rpm
rpm -Uvh lxc-4.0.3-2022080901.x86_64.rpm
rpm -Uvh lxc-devel-4.0.3-2022080901.x86_64.rpm
```

## 4. 构建lcr rpm包

### 4.1 安装lcr的依赖：
```shell
dnf --enablerepo=powertools install -y gtest-devel
```
**注意**： 安装lcr之前需要先安装上一步构建的lxc。

### 4.2 准备lcr构建环境
先下载lcr源码
```shell
git clone https://gitee.com/openeuler/lcr
```

把所需要的源码，patch， spec放到rpmbuild工作目录：
首先把源码打包
```shell
export RPM=~/rpmbuild
cd lcr
tar -zcvf lcr-2.0.tar.gz *
```

```shell
cp lcr-2.0.tar.gz $RPM/SOURCES/
cp *.spec $RPM/SPECS/
```

### 4.3 进行构建
```shell
cd ~/rpmbuild/SPECS
rpmbuild -ba lcr.spec
```
### 4.4 安装
构建成功后， rpm包会放在rpmbuild工作目录中的RPM目录中， 可以找到对应的rpm包然后用`rpm -Uvh`命令安装

## 5. 构建clibcni rpm包

### 5.1 安装clibcni的依赖： 
```shell
dnf --enablerepo=powertools install -y gmock-devel
```

### 5.2 准备clibcni构建环境
首先把源码打包
```shell
git clone https://gitee.com/openeuler/clibcni
cd clicni
tar -zcvf clibcni-2.0.tar.gz *
```

```shell
cp clibcni-2.0.tar.gz $RPM/SOURCES/
cp *.spec $RPM/SPECS/
```

### 5.3 进行构建
```shell
cd ~/rpmbuild/SPECS
rpmbuild -ba clibcni.spec
```
### 5.4 安装
构建成功后， rpm包会放在rpmbuild工作目录中的RPM目录中， 可以找到对应的rpm包然后用`rpm -Uvh`命令安装

## 6. 构建protobuf rpm包

### 6.1 安装protobuf的依赖： 
```shell
yum install -y emacs.x86_64
```

### 6.2 准备protobuf构建环境
```shell
git clone https://gitee.com/src-openeuler/protobuf 
cd protobuf
git checkout openEuler-20.03-LTS
cp *.tar.gz *.el *.patch $RPM/SOURCES/ && cp *.spec $RPM/SPECS/
```
由于我们不需要编译java和python的protobuf, 所以修改下spec文件最开始的5行， 可以避免安装相关的依赖：
```shell
cd ~/rpmbuild/SPECS
vim protobuf.spec
%bcond_with python
%bcond_with java
```

### 6.3 进行构建
```shell
rpmbuild -ba protobuf.spec
```
### 6.4 安装
构建成功后， rpm包会放在rpmbuild工作目录中的RPM目录中， 可以找到对应的rpm包然后用`rpm -Uvh`命令安装

## 7. 构建grpc rpm包

### 7.1 安装grpc的依赖： 
```shell
yum install -y emacs.x86_64 openssl-devel.x86_64
dnf --enablerepo=powertools install gflags-devel python3-Cython python3-devel
dnf install -y abseil-cpp-devel gperftools-devel re2-devel
```

### 7.2 准备grpc构建环境
```shell
git clone https://gitee.com/src-openeuler/grpc
cd grpc
git checkout openEuler-20.03-LTS
cp *.tar.gz $RPM/SOURCES/ && cp *.spec $RPM/SPECS/
```

### 7.3 进行构建
```shell
rpmbuild -ba grpc.spec
```

## 8. 构建iSulad rpm包

### 8.1 安装iSulad的依赖
```shell
dnf --enablerepo=powertools install http-parser-devel
dnf install -y sqlite-devel
```

### 8.2 准备iSulad构建环境
首先把源码打包
```shell
git clone https://gitee.com/openeuler/iSulad
cd iSulad/
tar -zcvf iSulad-2.1.tar.gz *
```
```shell
cp iSulad-2.1.tar.gz $RPM/SOURCES/
cp *.spec $RPM/SPECS/
```

### 8.3 进行构建
```shell
rpmbuild -ba iSulad.spec
```
