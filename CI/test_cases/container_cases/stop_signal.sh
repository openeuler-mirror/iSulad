#!/bin/bash
#
# attributes: isulad stop signal
# concurrent: NA
# spend time: 5

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
##- @Create: 2020-12-23
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_stop_signal() {
    local ret=0
    local image="busybox"
    local test="container stop signal test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return "${FAILURE}"

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -itd --stop-signal xxx $image /bin/sh 2>&1 | grep "Invalid signal: xxx"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid signal: xxx" && ((ret++))

    isula run -itd --stop-signal 90 $image /bin/sh 2>&1 | grep "Invalid signal: 90"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid signal: 90" && ((ret++))

    c_id=$(isula run -itd --stop-signal KILL $image sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Config.StopSignal}}' "$c_id" 2>&1 | grep "KILL"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check StopSignal: KILL" && ((ret++))

    isula stop "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop container ${c_id}" && ((ret++))

    isula rm -f "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    c_id=$(isula run -itd --stop-signal SIGKILL $image sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Config.StopSignal}}' "$c_id" 2>&1 | grep "SIGKILL"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check StopSignal: KILL" && ((ret++))

    isula stop "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop container ${c_id}" && ((ret++))

    isula rm -f "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    c_id=$(isula run -itd --stop-signal STOP $image sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Config.StopSignal}}' "$c_id" 2>&1 | grep "STOP"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check StopSignal: STOP" && ((ret++))

    pid=$(isula inspect --format='{{json .State.Pid}}' "$c_id")

    isula stop -t 20 "$c_id" &
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop container ${c_id}" && ((ret++))

    sleep 5

    cat /proc/"$pid"/status | grep stopped
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check send stop signal STOP" && ((ret++))

    isula rm -f "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

declare -i ans=0

test_stop_signal || ((ans++))

show_result "${ans}" "${curr_path}/${0}"
