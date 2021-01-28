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
##- @Description: generate cetification
##- @Author: lifeng
##- @Create: 2020-03-30
#######################################################################
set -xe
umask 0022

builddir=`env | grep BUILDDIR | awk -F '=' '{print $2}'`
if [ "x$builddir" == "x" ];then
    builddir=/usr/local
fi

buildstatus=${builddir}/build.fail

declare -a buildlogs
build_log_crictl=${builddir}/build.crictl.log
build_log_cni_plugins=${builddir}/build.cni_plugins.log
build_log_cni_dnsname=${builddir}/build.cni_dnsname.log
buildlogs+=(${build_log_crictl} ${build_log_cni_plugins} ${build_log_cni_dnsname})

mkdir -p ${builddir}/bin
mkdir -p ${builddir}/include
mkdir -p ${builddir}/lib
mkdir -p ${builddir}/lib/pkgconfig
mkdir -p ${builddir}/systemd/system

#install crictl
function make_crictl()
{
    cd ~
    git clone https://gitee.com/duguhaotian/cri-tools.git
    go version
    cd cri-tools
    git checkout v1.18.0
    make -j $nproc
    echo "make cri-tools: $?"
    cp ./_output/crictl ${builddir}/bin/
}

#install cni plugins
function make_cni_plugins()
{
    local CNI_PLUGINS_COMMIT=b93d284d18dfc8ba93265fa0aa859c7e92df411b
    cd ~
    git clone https://gitee.com/duguhaotian/plugins.git
    cd plugins
    ./build_linux.sh
    mkdir -p ${builddir}/cni/bin/
    cp bin/* ${builddir}/cni/bin/
}

#install cni dnsname
function make_cni_dnsname()
{
    cd ~
    git clone https://gitee.com/zh_xiaoyu/dnsname.git
    cd dnsname
    git checkout v1.1.1
    make
    mkdir -p ${builddir}/cni/bin/
    cp bin/* ${builddir}/cni/bin/
}

function check_make_status()
{
    set +e
    script_cmd="$1"
    log_file="$2"
    ${script_cmd} >${log_file} 2>&1
    if [ $? -ne 0 ];then
        cat ${log_file}
        touch ${buildstatus}
    fi
    rm -f $2
    set -e
}

rm -rf ${buildstatus}
check_make_status make_crictl ${build_log_crictl} &
check_make_status make_cni_plugins ${build_log_cni_plugins} &
check_make_status make_cni_dnsname ${build_log_cni_dnsname} &

# install lxc
cd ~
git clone https://gitee.com/src-openeuler/lxc.git
cd lxc
tar xf lxc-4.0.3.tar.gz
cd lxc-4.0.3
mv ../*.patch .
for var in $(ls 0*.patch | sort -n)
do
    patch -p1 < ${var}
done
sed -i 's/fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO/fd == 0 || fd == 1 || fd == 2 || fd >= 1000/g' ./src/lxc/start.c
./autogen.sh
./configure --prefix=${builddir}
make -j $(nproc)
make install
ldconfig

# install lcr
cd ~
git clone https://gitee.com/openeuler/lcr.git
cd lcr
git checkout origin/network
sed -i 's/fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO/fd == 0 || fd == 1 || fd == 2 || fd >= 1000/g' ./src/utils.c
mkdir -p build
cd build
cmake -DENABLE_UT=ON -DLIB_INSTALL_DIR=${builddir}/lib -DCMAKE_INSTALL_PREFIX=${builddir} ../
make -j $(nproc)
make install
cd -
ldconfig

# install runc
cd ~
if [ -d ./runc ];then
	rm -rf ./runc
fi
git clone https://gitee.com/src-openeuler/runc.git
cd runc
git checkout -q origin/openEuler-20.03-LTS
./apply-patch
mkdir -p .gopath/src/github.com/opencontainers
export GOPATH=`pwd`/.gopath
if [ -L .gopath/src/github.com/opencontainers/runc ];then
	echo "Link exist"
else
	ln -sf `pwd` .gopath/src/github.com/opencontainers/runc
fi

cd .gopath/src/github.com/opencontainers/runc
make -j $(nproc)
\cp -f ./runc ${builddir}/bin
cd -

wait
if [ -e ${buildstatus} ];then
    for i in ${buildlogs[@]}
    do
        if [ -e ${$i} ];then
            cat $i
        fi
    done
    exit 1
fi
