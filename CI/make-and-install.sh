#!/bin/sh
#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2020. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: lifeng
##- @Create: 2020-03-30
#######################################################################

PWD=`pwd`
basepath=$(cd `dirname $0`; pwd)
cd ${PWD}

set -xe

# install depend libs
builddir=`env | grep BUILDDIR | awk -F '=' '{print $2}'`
restbuilddir=${builddir}/rest
mkdir -p $builddir

mkdir -p $restbuilddir
mkdir -p $restbuilddir/bin
mkdir -p $restbuilddir/etc
mkdir -p $restbuilddir/include
mkdir -p $restbuilddir/lib
mkdir -p $restbuilddir/systemd

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:${builddir}/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:${builddir}/lib:$LD_LIBRARY_PATH
export C_INCLUDE_PATH=/usr/local/include:${builddir}/include:$C_INCLUDE_PATH
export CPLUS_INCLUDE_PATH=/usr/local/include:${builddir}/include:$CPLUS_INCLUDE_PATH
export PATH=${builddir}/bin:$PATH

ISULAD_SRC_PATH=`env | grep TOPDIR | awk -F '=' '{print $2}'`
export ISULAD_COPY_PATH=~/iSulad
export LCR_SRC_PATH=~/lcr/

export valgrind_log="/tmp/valgrind.log"
export PATH=$PATH:/usr/local/go/bin

umask 0022
cp -r $ISULAD_SRC_PATH $ISULAD_COPY_PATH

#Init GCOV configs
set +e
if [[ "x${GCOV}" == "xON" ]]; then
  export enable_gcov=1
fi
set -e

function echo_success()
{
    echo -e "\033[1;32m"$@"\033[0m"
}

function echo_error()
{
    echo -e "\033[1;31m"$@"\033[0m"
}

source $basepath/install_depends.sh

echo_success "===================RUN DT-LLT TESTCASES START========================="
cd $ISULAD_COPY_PATH
sed -i 's/fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO/fd == 0 || fd == 1 || fd == 2 || fd >= 1000/g' ./src/utils/cutils/utils.c
rm -rf build
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_UT=ON -DENABLE_SHIM_V2=ON -DENABLE_METRICS=ON ..
make -j $(nproc)
make install
ctest -T memcheck --output-on-failure
if [[ $? -ne 0 ]]; then
    exit 1
fi
echo_success "===================RUN DT-LLT TESTCASES END========================="

# build fuzz
cd $ISULAD_COPY_PATH
rm -rf build
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_FUZZ=ON ..
make -j $(nproc)

# build rest version
cd $ISULAD_COPY_PATH
rm -rf build
mkdir build
cd build
cmake -DLIB_INSTALL_DIR=${restbuilddir}/lib -DCMAKE_INSTALL_PREFIX=${restbuilddir} -DCMAKE_INSTALL_SYSCONFDIR=${restbuilddir}/etc -DENABLE_EMBEDDED=ON -DENABLE_GRPC=OFF -DDISABLE_OCI=ON ..
make -j $(nproc)
make install
sed -i 's/"log-driver": "stdout"/"log-driver": "file"/g' ${restbuilddir}/etc/isulad/daemon.json
sed -i "/registry-mirrors/a\        \"https://3laho3y3.mirror.aliyuncs.com\"" ${restbuilddir}/etc/isulad/daemon.json

#build grpc version
cd $ISULAD_COPY_PATH
rm -rf build
mkdir build
cd build
if [[ ${enable_gcov} -ne 0 ]]; then
  cmake -DLIB_INSTALL_DIR=${builddir}/lib -DCMAKE_INSTALL_PREFIX=${builddir} -DCMAKE_INSTALL_SYSCONFDIR=${builddir}/etc -DCMAKE_BUILD_TYPE=Debug -DGCOV=ON -DENABLE_EMBEDDED=ON -DENABLE_COVERAGE=ON -DENABLE_UT=ON -DENABLE_METRICS=ON ..
else
  cmake -DLIB_INSTALL_DIR=${builddir}/lib -DCMAKE_INSTALL_PREFIX=${builddir} -DCMAKE_INSTALL_SYSCONFDIR=${builddir}/etc -DENABLE_EMBEDDED=ON -DENABLE_METRICS=ON ..
fi
make -j $(nproc)
make install
sed -i 's/"log-driver": "stdout"/"log-driver": "file"/g' ${builddir}/etc/isulad/daemon.json
sed -i "/registry-mirrors/a\        \"https://3laho3y3.mirror.aliyuncs.com\"" ${builddir}/etc/isulad/daemon.json
