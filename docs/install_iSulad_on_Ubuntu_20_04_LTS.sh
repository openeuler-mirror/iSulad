#!/bin/bash

set -x
set -e

# export LDFLAGS
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:/lib/x86_64-linux-gnu/:$LD_LIBRARY_PATH
echo "/usr/local/lib" >> /etc/ld.so.conf
apt install -y g++ libprotobuf-dev protobuf-compiler protobuf-compiler-grpc libgrpc++-dev libgrpc-dev libtool automake autoconf cmake make pkg-config libyajl-dev zlib1g-dev libselinux1-dev libseccomp-dev libcap-dev libsystemd-dev git libarchive-dev libcurl4-gnutls-dev openssl libdevmapper-dev python3 libtar0 libtar-dev libhttp-parser-dev libwebsockets-dev

BUILD_DIR=/tmp/build_isulad

rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# build lxc
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/lxc.git
cd lxc
tar -zxf lxc-4.0.3.tar.gz
./apply-patches
cd lxc-4.0.3
./autogen.sh
./configure
make -j $(nproc)
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
