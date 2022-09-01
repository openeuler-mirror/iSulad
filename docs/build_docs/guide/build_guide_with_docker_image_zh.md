# 搭建iSulad开发环境

本文主要是指导iSulad社区开发者，如何快速构建iSulad的开发、编译、运行、测试环境。减少环境准备的成本。

## 准备编译容器镜像

以openEuler-21.03的docker镜像为例。
首先从官方网站下载对应的镜像：`wget https://repo.openeuler.org/openEuler-21.03/docker_img/x86_64/openEuler-docker.x86_64.tar.xz`

以docs提供的[dockerfile](./dockerfiles/isulad_build_in_openeuler.Dockerfile)，准备构建基础镜像：
```bash
$ mkdir -p ./build-home
$ cp docs/dockerfiles/isulad_build_in_openeuler.Dockerfile ./build-home
$ pushd build-home
$ docker build -t isulad_build:v1 -f isulad_build_in_openeuler.Dockerfile .
$ popd
```

## 从源码构建

### 启动构建容器

```bash
$ docker run -itd -v /root/tmp/:/var/lib/isulad -v /sys/fs/cgroup/:/sys/fs/cgroup -v /lib/modules:/lib/modules --tmpfs /tmp:exec,mode=777 --tmpfs /run:exe
c,mode=777 --privileged isulad_build:v1 sh
```

注意：
- 需要挂载一个主机目录到容器中，用于isulad的工作目录；
- 需要privileged权限；
- 需要挂入modules目录；

### 编译安装lxc
```bash
git clone https://gitee.com/src-openeuler/lxc.git
pushd lxc
rm -rf lxc-4.0.3
./apply-patches || exit 1
pushd lxc-4.0.3
./autogen.sh && ./configure || exit 1
make -j $(nproc) || exit 1
make install
popd
popd
```

### 编译安装lcr
```bash
ldconfig
git clone https://gitee.com/openeuler/lcr.git
pushd lcr
rm -rf build
mkdir build
pushd build
cmake -DDEBUG=ON -DCMAKE_SKIP_RPATH=TRUE ../ || exit 1
make -j $(nproc) || exit 1
make install
popd
popd
```

### 编译安装clibcni
```bash
ldconfig
git clone https://gitee.com/openeuler/clibcni.git
pushd clibcni
rm -rf build
mkdir build
pushd build
cmake -DDEBUG=ON ../ || exit 1
make -j $(nproc) || exit 1
make install
popd
popd
```

### 编译安装lib-shim-v2
```bash
mkdir -p ~/.cargo
touch ~/.cargo/config
echo "[source.crates-io]" >> ~/.cargo/config
echo "[source.local-registry]" >> ~/.cargo/config
echo "directory = \"vendor\"" >> ~/.cargo/config

ldconfig
rm -rf lib-shim-v2
git clone https://gitee.com/src-openeuler/lib-shim-v2.git
pushd lib-shim-v2
tar -zxf lib-shim-v2-0.0.1.tar.gz
pushd lib-shim-v2-0.0.1
make lib || exit 1
make install
popd
popd
```

### 编译安装iSulad
```bash
ldconfig
rm -rf iSulad
git clone https://gitee.com/openeuler/iSulad.git
pushd iSulad
# 修改代码
rm -rf build
mkdir build
pushd build
cmake -DDEBUG=ON -DENABLE_UT=ON -DENABLE_SHIM_V2=ON ../ || exit 1
make -j $(nproc) || exit 1
make install
# 运行UT测试保障修改无问题
ctest -V || exit 1
popd
popd
```
