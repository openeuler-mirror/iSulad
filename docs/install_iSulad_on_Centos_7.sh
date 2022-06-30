#！/bin/bash


set -x
set -e

# install neccessary packages
yum install -y patch automake autoconf libtool cmake make libcap libcap-devel libselinux libselinux-devel libseccomp libseccomp-devel yajl-devel git libcgroup tar python3 python3-pip device-mapper-devel libcurl-devel zlib-devel glibc-headers openssl-devel gcc gcc-c++ systemd-devel systemd-libs golang libtar libtar-devel

# export LDFLAGS
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH
  echo "/usr/local/lib" >> /etc/ld.so.conf

BUILD_DIR=/tmp/build_isulad

rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# build libarchive
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/libarchive.git
cd libarchive
git checkout -b openEuler-20.03-LTS-tag openEuler-20.03-LTS-tag
tar -zxvf libarchive-3.4.1.tar.gz
cd libarchive-3.4.1
patch -p1 -F1 -s < ../libarchive-uninitialized-value.patch
cd build
cmake -DCMAKE_USE_SYSTEM_LIBRARIES=ON ../
make -j $(nproc)
make install
ldconfig

# build protobuf
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/protobuf.git
cd protobuf
git checkout openEuler-20.03-LTS-tag
tar -xzvf protobuf-all-3.9.0.tar.gz
cd protobuf-3.9.0
./autogen.sh
./configure
make -j $(nproc)
make install
ldconfig

# build c-ares
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/c-ares.git
cd c-ares
git checkout openEuler-20.03-LTS-tag
tar -xzvf c-ares-1.15.0.tar.gz
cd c-ares-1.15.0
autoreconf -if
./configure --enable-shared --disable-dependency-tracking
make -j $(nproc)
make install
ldconfig

# build grpc
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/grpc.git
cd grpc
git checkout openEuler-20.03-LTS-tag
tar -xzvf grpc-1.22.0.tar.gz
cd grpc-1.22.0
make -j $(nproc)
make install
ldconfig

# build http_parser
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/http-parser.git
cd http-parser
git checkout openEuler-20.03-LTS-tag
tar -xzvf http-parser-2.9.2.tar.gz
cd http-parser-2.9.2
make -j CFLAGS="-Wno-error"
make CFLAGS="-Wno-error" install
ldconfig

# build libwebsockets
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/libwebsockets.git
cd libwebsockets
git checkout openEuler-20.03-LTS-tag
tar -xzvf libwebsockets-2.4.2.tar.gz
cd libwebsockets-2.4.2
patch -p1 -F1 -s < ../libwebsockets-fix-coredump.patch
mkdir build
cd build
cmake -DLWS_WITH_SSL=0 -DLWS_MAX_SMP=32 -DCMAKE_BUILD_TYPE=Debug ../
make -j $(nproc)
make install
ldconfig

# build lxc
cd $BUILD_DIR
git clone https://gitee.com/src-openeuler/lxc.git
cd lxc
tar -zxf lxc-4.0.3.tar.gz
./apply-patches
cd lxc-4.0.3
./autogen.sh
./configure
make -j
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
mkdir build
cd build
cmake ..
make
make install
