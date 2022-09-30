# Build guide with docker image

This guide is mainly about how to use the image to quickly build the development environment of iSulad. Reduce the cost of environmental preparation.

## Prepare the container image

Take the docker image of openEuler-21.03 as an example.

First download the image from the official website: `wget https://repo.openeuler.org/openEuler-21.03/docker_img/x86_64/openEuler-docker.x86_64.tar.xz`

Prepare to build the base image with the [dockerfile](./dockerfiles/isulad_build_in_openeuler.Dockerfile) provided by the docs：

```bash
$ mkdir -p ./build-home
$ cp docs/dockerfiles/isulad_build_in_openeuler.Dockerfile ./build-home
$ pushd build-home
$ docker build -t isulad_build:v1 -f isulad_build_in_openeuler.Dockerfile .
$ popd
```

## build and install isulad

### run container

```bash
$ docker run -itd -v /root/tmp/:/var/lib/isulad -v /sys/fs/cgroup/:/sys/fs/cgroup -v /lib/modules:/lib/modules --tmpfs /tmp:exec,mode=777 --tmpfs /run:exe
c,mode=777 --privileged isulad_build:v1 sh
```

**Note**：

- A host directory must be mounted to the container for isulad's working directory;
- Requires privileged permission;
- Must be linked to the modules directory;

### build and install lxc

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

### build and install lcr

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

### build and install clibcni

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

### build and install lib-shim-v2

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

### build and install iSulad

```bash
ldconfig
rm -rf iSulad
git clone https://gitee.com/openeuler/iSulad.git
pushd iSulad
# modify code
rm -rf build
mkdir build
pushd build
cmake -DDEBUG=ON -DENABLE_UT=ON -DENABLE_SHIM_V2=ON ../ || exit 1
make -j $(nproc) || exit 1
make install
# Run UT test to ensure correct modification
ctest -V || exit 1
popd
popd
```

