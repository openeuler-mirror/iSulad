#！/bin/bash


set -x
set -e

# install neccessary packages
# yum install -y patch automake autoconf libtool cmake make libcap libcap-devel libselinux libselinux-devel libseccomp libseccomp-devel yajl-devel git libcgroup tar python3 python3-pip device-mapper-devel libcurl-devel zlib-devel glibc-headers openssl-devel gcc gcc-c++ systemd-devel systemd-libs golang libtar libtar-devel which

# export LDFLAGS
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH
echo "/usr/local/lib" >> /etc/ld.so.conf

BUILD_DIR=/tmp/build_isulad

rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# build lxc
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/lxc.git
cd lxc
git config --global --add safe.directory $BUILD_DIR/lxc/lxc-5.0.2
./apply-patches
cd lxc-5.0.2
sed -i 's/return open(rpath, (int)((unsigned int)flags | O_CLOEXEC));/return open(rpath, (int)((unsigned int)flags | O_CLOEXEC), 0);/g' src/lxc/isulad_utils.c
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
make -j
make install

# build and install clibcni
cd $BUILD_DIR
git clone https://gitee.com/openeuler/clibcni.git
cd clibcni
mkdir build
cd build
cmake ..
make -j
make install

# build and install iSulad
cd $BUILD_DIR
git clone https://gitee.com/openeuler/iSulad.git
cd iSulad
sed -i 's/-O2 -Wall -fPIE/-O2 -Wall -fPIE -std=gnu99/g' cmake/set_build_flags.cmake
mkdir build
cd build
cmake -DDISABLE_WERROR=on ../
make
make install
