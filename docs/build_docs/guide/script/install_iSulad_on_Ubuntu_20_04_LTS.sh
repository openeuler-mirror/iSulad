#!/bin/bash

set -x
set -e

# export LDFLAGS
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:/lib/x86_64-linux-gnu/:$LD_LIBRARY_PATH
echo "/usr/local/lib" >> /etc/ld.so.conf


if [ ! -e "/etc/timezone" ]; then
    export TZ=Asia/Shanghai
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
fi

apt update -y && apt upgrade -y
apt install -y g++ systemd libprotobuf-dev protobuf-compiler protobuf-compiler-grpc libgrpc++-dev libgrpc-dev libtool automake autoconf cmake make pkg-config libyajl-dev zlib1g-dev libselinux1-dev libseccomp-dev libcap-dev libsystemd-dev git libarchive-dev libcurl4-gnutls-dev openssl libdevmapper-dev python3 libtar0 libtar-dev libwebsockets-dev

apt install -y runc

apt install -y docbook2x ninja-build meson
apt install -y libncurses-dev

BUILD_DIR=/tmp/build_isulad

git config --global http.sslverify false

rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# build lxc
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/lxc.git
cd lxc
git config --global --add safe.directory $BUILD_DIR/lxc/lxc-5.0.2
./apply-patches
cd lxc-5.0.2
meson setup -Disulad=true \
    -Dprefix=/usr build
meson compile -C build
make install

# build lcr
cd $BUILD_DIR
git clone https://gitee.com/openeuler/lcr.git
cd lcr
mkdir build
cd build
cmake ..
make -j $(nproc)
make install

# build and install clibcni
cd $BUILD_DIR
git clone https://gitee.com/openeuler/clibcni.git
cd clibcni
mkdir build
cd build
cmake ..
make -j $(nproc)
make install

# build and install iSulad
cd $BUILD_DIR
git clone https://gitee.com/openeuler/iSulad.git
cd iSulad
mkdir build
cd build
cmake ..
make -j $(nproc)
make install

# clean
rm -rf $BUILD_DIR
apt autoremove
