#!/bin/bash
#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:provide gateway checker for pull request of iSulad
##- @Author: haozi007
##- @Create: 2021-12-06
#######################################################################
tbranch="master"
if [ $# -eq 1 ]; then
    tbranch=$1
fi

dnf install -y gtest-devel gmock-devel diffutils cmake gcc-c++ yajl-devel patch make libtool libevent-devel libevhtp-devel grpc grpc-plugins grpc-devel protobuf-devel libcurl libcurl-devel sqlite-devel libarchive-devel device-mapper-devel http-parser-devel libseccomp-devel libcap-devel libselinux-devel libwebsockets libwebsockets-devel systemd-devel git chrpath

# dnf install -y cargo rust rust-packaging

cd ~

rm -rf lxc
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

ldconfig
rm -rf lcr
git clone https://gitee.com/openeuler/lcr.git
pushd lcr
git checkout ${tbranch}
rm -rf build
mkdir build
pushd build
cmake -DDEBUG=ON -DCMAKE_SKIP_RPATH=TRUE ../ || exit 1
make -j $(nproc) || exit 1
make install
popd
popd

# build iSulad with restful
ldconfig
pushd iSulad
rm -rf build
mkdir build
pushd build
cmake -DDEBUG=ON -DCMAKE_INSTALL_PREFIX=/usr -DEANBLE_IMAGE_LIBARAY=OFF -DENABLE_SHIM_V2=OFF -DENABLE_GRPC=OFF  ../ || exit 1
make -j $(nproc) || exit 1
popd
popd

# build iSulad with least modules
ldconfig
pushd iSulad
rm -rf build
mkdir build
pushd build
cmake -DDEBUG=ON -DCMAKE_INSTALL_PREFIX=/usr -DEANBLE_IMAGE_LIBARAY=OFF -DENABLE_OPENSSL_VERIFY=OFF -DENABLE_SYSTEMD_NOTIFY=OFF -DENABLE_SHIM_V2=OFF -DENABLE_GRPC=OFF -DENABLE_NATIVE_NETWORK=OFF -DDISABLE_OCI=ON ../ || exit 1
make -j $(nproc) || exit 1
popd
popd

# build iSulad with grpc and static library
ldconfig
pushd iSulad
rm -rf build
mkdir build
pushd build
cmake -DUSESHARED=OFF -DCMAKE_INSTALL_PREFIX=/usr -DENABLE_SHIM_V2=OFF ../ || exit 1
make -j $(nproc) || exit 1
popd
popd

# build iSulad with grpc
ldconfig
pushd iSulad
rm -rf build
mkdir build
pushd build
cmake -DDEBUG=ON -DCMAKE_INSTALL_PREFIX=/usr -DENABLE_UT=ON -DENABLE_SHIM_V2=OFF ../ || exit 1
make -j $(nproc) || exit 1
ctest -V
popd
popd