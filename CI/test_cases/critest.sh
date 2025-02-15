#!/bin/bash
#
# attributes: critest
# concurrent: YES
# spend time: 1500

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
##- @Description:CI
##- @Author: zhongtao
##- @Create: 2023-06-05
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ./helpers.sh
data_path=$(realpath $curr_path/container_cases/criconfigs)
pause_img_path=$(realpath $curr_path/container_cases/test_data)
image_arr=($(isula images | awk 'NR>1{print $1}'))

builddir=`env | grep BUILDDIR | awk -F '=' '{print $2}'`
if [ "x$builddir" == "x" ];then
    builddir=/usr/local
fi

function perpare_selinux_environment() {
    chcon system_u:object_r:container_runtime_exec_t:s0 $(whereis isula | awk '{print $2}')
    chcon system_u:object_r:container_runtime_exec_t:s0 /usr/bin/lxc-*
    chcon system_u:object_r:container_runtime_exec_t:s0 /usr/local/bin/lxc-*
    chcon system_u:object_r:container_runtime_exec_t:s0 $(whereis runc | awk '{print $2}')
    chcon system_u:object_r:container_runtime_exec_t:s0 $(whereis isulad-shim | awk '{print $2}')

    chcon -R system_u:object_r:container_file_t:s0 /var/lib/isulad

    chcon -R system_u:object_r:container_var_run_t:s0 /var/run/isula
    chcon -R system_u:object_r:container_var_run_t:s0 /var/run/isulad
    chcon system_u:object_r:container_var_run_t:s0 /var/run/isulad.pid
    chcon system_u:object_r:container_var_run_t:s0 /var/run/isulad.sock
}

function restore_selinux_environment() {
    chcon system_u:object_r:bin_t:s0 $(whereis isula | awk '{print $2}')
    chcon system_u:object_r:bin_t:s0 /usr/bin/lxc-*
    chcon system_u:object_r:bin_t:s0 /usr.local/bin/lxc-*
    chcon system_u:object_r:bin_t:s0 $(whereis runc | awk '{print $2}')
    chcon system_u:object_r:bin_t:s0 $(whereis isulad-shim | awk '{print $2}')

    chcon -R system_u:object_r:var_lib_t:s0 /var/lib/isulad

    chcon -R unconfined_u:object_r:var_run_t:s0 /var/run/isula
    chcon -R unconfined_u:object_r:var_run_t:s0 /var/run/isulad
    chcon unconfined_u:object_r:var_run_t:s0 /var/run/isulad.pid
    chcon unconfined_u:object_r:var_run_t:s0 /var/run/isulad.sock
}

function pre_test() {
    # build critest
    local VERSION="v1.25.0"

    rm -rf cri-tools
    git clone https://gitee.com/duguhaotian/cri-tools.git
    go version
    cd cri-tools
    git checkout ${VERSION}
    make -j $nproc
    echo "make cri-tools: $?"
    cp ./build/bin/critest ${builddir}/bin/

    critest --version

    # config pause
    init_cri_conf $1
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to init cri conf: ${1}" && return ${FAILURE}

    # config cni
    init_cni_conf $data_path
    if [ $? -ne 0 ]; then
        msg_err "Failed to init cni config"
        TC_RET_T=$(($TC_RET_T + 1))
        return $TC_RET_T
    fi

    # config selinux
    perpare_selinux_environment

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - memory leak" && return ${FAILURE}

    start_isulad_without_valgrind --selinux-enabled --network-plugin cni
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad with selinux and cni failed"  && return ${FAILURE}
}

function post_test() {
    restore_selinux_environment
    rm -rf ./cri-tools
    rm /usr/local/bin/critest

    restore_cri_conf
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restore cri conf"  && ((ret++))

    # clear env
    isula rm -f `isula ps -qa`
    isula rmi `isula images | awk 'NR>1{print $3}'`
    # restore images
    for image in "${image_arr[@]}"
    do
        isula pull ${image}
    done

    return ${ret}
}

function test_critest() {
    critest --runtime-endpoint=unix:///var/run/isulad.sock >> ${testcase_data}/critest.log
}

function do_test_t() {
    local ret=0

    local runtime="runc"
    local test="critest => $runtime"
    msg_info "${test} starting..."
    echo "${test}" >> ${testcase_data}/critest.log

    test_critest

    msg_info "${test} finished with return ${ret}..."

    stop_isulad_without_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    # replace default runtime
    sed -i 's/"default-runtime": "runc"/"default-runtime": "lcr"/g' /etc/isulad/daemon.json
    start_isulad_without_valgrind --selinux-enabled --network-plugin cni
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad with selinux and cni failed" && ((ret++))
    
    runtime=lcr
    test="critest => $runtime"
    msg_info "${test} starting..."
    echo "${test}" >> ${testcase_data}/critest.log

    test_critest

    msg_info "${test} finished with return ${ret}..."
    return $ret
}

function do_critest_test_t()
{
    local cri_version=$1
    local ret=0
    local test="do_critest_test_t => (${cri_version})"
    msg_info "${test} starting..."

    pre_test $cri_version || (ret++)

    do_test_t || ((ret++))

    post_test || (ret++)

    msg_info "${test} finished with return ${ret}..."

    return $ret
}

declare -i ans=0

for version in ${CRI_LIST[@]};
do
    do_critest_test_t $version
    if [ $? -ne 0 ];then
        let "ans=$ans + 1"
    fi
done

show_result ${ans} "${curr_path}/${0}"
