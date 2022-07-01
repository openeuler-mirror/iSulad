#!/bin/bash
#
# attributes: isulad basic container hook
# concurrent: NA
# spend time: 5

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
##- @Author: lifeng
##- @Create: 2020-06-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_stats_spec()
{
    local ret=0
    local image="busybox"
    local test="container stats test => (${FUNCNAME[@]})"
    statslog=/tmp/stats.log

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula stats xxxxxx 2>&1 | grep "No such container"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula stats - 2>&1 | grep "Invalid container name"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    container_name_init=stats_inited
    id_init=`isula create -t -n $container_name_init $image /bin/sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    container_name_running=stats_running
    id_running=`isula run -td -n $container_name_running $image /bin/sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula stats --no-stream > $statslog
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    cat $statslog | grep "${id_running:0:12}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula stats --no-stream -a > $statslog
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    cat $statslog | grep "${id_running:0:12}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    cat $statslog | grep "${id_init:0:12}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula stats --no-stream "$id_init" > $statslog
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    cat $statslog | grep "${id_init:0:12}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    container_name_pause=stats_paused
    id_pause=`isula run -td -n $container_name_pause $image /bin/sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula pause $id_pause
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pause running container" && ((ret++))

    container_name_stop=stats_stopped
    id_stop=`isula run -td -n $container_name_stop $image /bin/sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula stop -t 0 $id_stop
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop running container" && ((ret++))

    isula stats --original > $statslog
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stats --original" && ((ret++))

    cat $statslog | grep "${id_init:0:12}"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stats the inited container(should not)" && ((ret++))

    cat $statslog | grep "${id_running:0:12}" | grep "running"| grep "$container_name_running"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stats running container" && ((ret++))

    cat $statslog | grep "${id_pause:0:12}" | grep "paused"| grep "$container_name_pause"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stats paused container" && ((ret++))

    cat $statslog | grep "${id_stop:0:12}"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stats exited container(should not)" && ((ret++))

    isula stats --original -a > $statslog
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stats--original -a" && ((ret++))

    cat $statslog | grep "${id_init:0:12}" | grep "inited" | grep "$container_name_init"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stats inited container" && ((ret++))

    cat $statslog | grep "${id_running:0:12}" | grep "running"| grep "$container_name_running"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stats running container" && ((ret++))

    cat $statslog | grep "${id_pause:0:12}" | grep "paused"| grep "$container_name_pause"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stats paused container" && ((ret++))

    cat $statslog | grep "${id_stop:0:12}" | grep "exited"| grep "$container_name_stop"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stats exited container" && ((ret++))

    isula unpause $id_pause
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to unpause the paused container" && ((ret++))

    isula rm -f "$container_name_init" "$container_name_running" "$container_name_pause" "$container_name_stop"

    rm -f $statslog

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_stats_spec || ((ans++))

show_result ${ans} "${curr_path}/${0}"
