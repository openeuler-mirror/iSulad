#!/bin/bash
#
# attributes: isulad seccomp run
# concurrent: NO
# spend time: 4

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: chengzeruizhi
##- @Create: 2022-07-29
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
test_data_path=$(realpath $curr_path/test_data)
source ../helpers.sh

function do_pre() {
    local ret=0

    isula rm -f $(isula ps -qa)

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    return $ret
}

function do_test() {
    local ret=0

    msg_info "this is $0 do_test"

    cid1=$(isula run -tid --security-opt seccomp=/etc/isulad/seccomp_default.json busybox sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to run container with the default seccomp profile" && ((ret++))

    cid2=$(isula run -tid --security-opt seccomp=${test_data_path}/seccomp_profile_without_archmap.json busybox sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to run container with a customized seccomp profile" && ((ret++))

    cid3=$(isula run -tid --security-opt seccomp=/etc/isulad/seccomp_default.json \
        --security-opt seccomp=${test_data_path}/seccomp_profile_without_archmap.json busybox sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to run container with multiple seccomp profiles" && ((ret++))

    isula stop "${cid1}" "${cid2}" "${cid3}"

    isula rm -f $(isula ps -qa)

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function do_post() {
    check_valgrind_log
    start_isulad_with_valgrind
}

declare -i ans=0

do_pre || ((ans++))

do_test || ((ans++))

do_post

show_result ${ans} "${curr_path}/${0}"
