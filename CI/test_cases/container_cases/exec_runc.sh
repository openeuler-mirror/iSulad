#!/bin/bash
#
# attributes: isulad container stream exec with runc
# concurrent: NA
# spend time: 14

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
##- @Author: zhangxiaoyu
##- @Create: 2022-12-28
#######################################################################
declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

test="exec_runc_test => (${FUNCNAME[@]})"

function exec_runc_test()
{
    local ret=0
    local image="ubuntu"
    local container_name="test_busybox"

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -itd -n ${container_name} --runtime runc ${image} sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    ID=$(isula inspect -f '{{.Id}}' ${container_name})
    [[ "x$ID" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to get container ID" && ((ret++))

    isula exec -it $container_name date
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to exec date" && ((ret++))

    ls /var/run/isulad/runc/${ID}/exec/
    ls /var/run/isulad/runc/${ID}/exec/ | wc -l | grep 0
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - residual dir after success exec" && ((ret++))

    isula exec -it $container_name datee
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec success, but should failed" && ((ret++))

    ls /var/run/isulad/runc/${ID}/exec/
    ls /var/run/isulad/runc/${ID}/exec/ | wc -l | grep 0
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - residual dir after failed exec" && ((ret++))

    isula exec -ti $container_name dd if=/dev/zero of=test2 bs=1GB count=2
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to exec dd" && ((ret++))

    isula exec $container_name cat test2 &> test_exec
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to exec cat" && ((ret++))

    ls -l -h test_exec
    ls -l -h test_exec 2>&1 | grep "1.9G"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec data loss" && ((ret++))

    isula exec $container_name bash -c "sleep 999 & exit"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to exec backgrounder" && ((ret++))

    isula exec -ti $container_name bash -c "sleep 999 & exit"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - resize failed" && ((ret++))

    rm test_exec
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm test_execs" && ((ret++))

    isula rm -f ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - remove container ${container_name} failed" && ((ret++))

    ls /var/run/isulad/runc/${ID}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - residual dir after delete container" && ((ret++))

    return ${ret}
}

declare -i ans=0

msg_info "${test} starting..."

exec_runc_test || ((ans++))

msg_info "${test} finished with return ${ret}..."

show_result ${ans} "${curr_path}/${0}"
