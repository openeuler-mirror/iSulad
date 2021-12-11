#!/bin/bash
#
# attributes: isulad daemon events
# concurrent: NA
# spend time: 3

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
##- @Author: WuJing
##- @Create: 2020-07-07
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_events() {
    local ret=0
    local image="busybox"
    local test="isula events command test => (${FUNCNAME[@]})"
    start_time=$(date +"%Y-%m-%dT%H:%M:%S")
    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return "${FAILURE}"

    msg_info "${test} starting..."

    isula images | grep ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    container_name="test"
    isula run -itd -n ${container_name} ${image} /bin/sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    local cmd="ls"
    isula exec -it ${container_name} ${cmd}
    sleep 1 # To include the end time
    end_time=$(date +"%Y-%m-%dT%H:%M:%S")

    isula events --since "${start_time}" --until "${end_time}" | grep "image pull busybox"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - lose image pull event" && ((ret++))

    isula events --since "${start_time}" --until "${end_time}" -n ${container_name} | grep "container create" | grep ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - lose container create event" && ((ret++))

    isula events --since "${start_time}" --until "${end_time}" -n ${container_name} | grep "container start" | grep ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - lose container start event" && ((ret++))

    isula events --since "${start_time}" --until "${end_time}" -n ${container_name} \
        | grep "container exec_create" | grep ${cmd} | grep ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - lose container exec_create" && ((ret++))

    isula events --since "${start_time}" --until "${end_time}" -n ${container_name} \
        | grep "container exec_start" | grep ${cmd} | grep ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - lose container exec_start" && ((ret++))

    isula events --since "${start_time}" --until "${end_time}" -n ${container_name} \
        | grep "container exec_die" | grep ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - lose container exec_die" && ((ret++))

    isula rm -f ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container: ${container_name}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

declare -i ans=0

test_events || ((ans++))

show_result "${ans}" "${curr_path}/${0}"
