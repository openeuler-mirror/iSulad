#!/bin/bash
#
# attributes: isulad basic cri seccomp
# concurrent: NA
# spend time: 4

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: wangfengtu
##- @Create: 2022-08-13
#######################################################################

source ../helpers.sh
curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/criconfigs)
pause_img_path=$(realpath $curr_path/test_data)

function do_pre()
{
  sed -i "s#seccomp_localhost_ref#${data_path}/seccomp_localhost.json#g" ${data_path}/container-config-seccomp-localhost.json

  init_cri_conf $1 "without_valgrind"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to init cri conf: ${1}" && return ${FAILURE}
  
  isula pull busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull busybox" && return ${FAILURE}

  return 0
}

function do_post()
{
    local ret=0
    restore_cri_conf "without_valgrind"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restore cri conf" && ((ret++))
    return $ret
}

function test_cri_stats()
{
    local ret=0
    local test="cri stats test => (${FUNCNAME[@]})"
    
    msg_info "${test} starting..."

    sid=$(crictl runp ${data_path}/sandbox-config.json)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run sandbox" && ((ret++))

    cid=$(crictl create $sid ${data_path}/container-config.json ${data_path}/sandbox-config.json)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container" && ((ret++))

    crictl start $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start container" && ((ret++))
    
    crictl statsp $sid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to get cri stats" && ((ret++))

    crictl stats $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to get cri stats" && ((ret++))
    
    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

for version in ${CRI_LIST[@]};
do
    test="test_cri_test_fun, use cri version => (${version})"
    msg_info "${test} starting..."

    do_pre $version || ((ans++))

    test_cri_stats || ((ans++))

    do_post || ((ans++))
    msg_info "${test} finished with return ${ans}..."
done

show_result ${ans} "${curr_path}/${0}"

