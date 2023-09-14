#!/bin/bash
#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description: build isulad on many linux distros
##- @Author: haozi007
##- @Create: 2023-09-14
#######################################################################

set +e
set -x

support_shim_v2=0

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH
cd ~

# install lib-shim-v2
if [ ${support_shim_v2} -ne 0 ]; then
    source ${HOME}/.cargo/env
    rm -rf lib-shim-v2
    git clone https://gitee.com/openeuler/lib-shim-v2.git
    pushd lib-shim-v2
    mkdir .cargo
cat >> ./.cargo/config << EOF
[source.crates-io]
replace-with = "local-registry"
[source.local-registry]
directory = "vendor"
EOF
    cargo build --release
    make install
    popd
    ldconfig
fi

# install lxc
git clone https://gitee.com/src-openeuler/lxc.git
pushd lxc/
git checkout origin/openEuler-22.03-LTS-SP1
./apply-patches
pushd lxc-4.0.3
./autogen.sh
./configure --disable-silent-rules --disable-rpath --disable-static \
    --disable-apparmor --enable-selinux --enable-seccomp --disable-werror
make && make install
popd
popd

git clone https://gitee.com/openeuler/lcr.git
pushd lcr
mkdir build && pushd build
cmake -DENABLE_UT=ON ../
make -j2 && make install
ctest -V
popd
popd

git clone https://gitee.com/openeuler/iSulad.git
pushd iSulad
mkdir build && pushd build
cmake -DENABLE_UT=ON ../
make -j2 && make install
ctest -V
popd
popd
