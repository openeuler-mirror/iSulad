#!/bin/bash
#
# attributes: isula container with restartpolicy and network
# concurrent: NO
# spend time: 28

#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2021. All rights reserved.
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
##- @Create: 2021-04-02
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh

if [ ${enable_native_network} -ne 0 ]; then
    msg_info "${test} disable native network, just ignore test." 
    exit 0
fi

network_name="cni1"
cont_name="cont_name"

function test_container_and_kill()
{
    wait_container_status ${cont_name} "running"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - wait cont ${cont_name} running failed " && return ${FAILURE}

    IP=$(isula inspect -f '{{json .NetworkSettings.Networks.'${network_name}'.IPAddress }}' ${cont_name} | sed 's/\"//g')
    [[ "x${IP}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ${cont_name} ${network_name} IP failed " && return ${FAILURE}

    ping -c 3 -w 10 ${IP}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP} failed " && return ${FAILURE}

    PID=$(isula inspect -f {{.State.Pid}} ${cont_name})
    [[ "x${PID}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect container ${cont_name} PID failed" && return ${FAILURE}

    kill -9 ${PID}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - kill PID ${PID} failed " && return ${FAILURE}

    for i in $(seq 1 20); do
        ls /proc | grep ${pid}
        if [ $? -ne 0 ]; then
            break
        fi
        sleep 2
    done

    # wait container clean up resource
    sleep 5
}

function test_restartpolicy_and_networks()
{
    local ret=0
    local test="restartpolicy and networks test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    # create network
    isula network create ${network_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${network_name} failed" && return ${FAILURE}

    # run container with network and restart policy
    cont_id=$(isula run -tid --net ${network_name} --restart on-failure:3 -n ${cont_name} busybox sh)
    [[ "x${cont_id}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont_name} with network ${network_name} ${network_name2} failed" && return ${FAILURE}

    netns=$(isula inspect -f {{.NetworkSettings.SandboxKey}} ${cont_name})
    [[ "x${netns}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect netns failed" && return ${FAILURE}

    for i in $(seq 1 4)
    do
        test_container_and_kill
    done

    wait_container_status ${cont_name} "exited"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - wait cont ${cont_name} running failed " && return ${FAILURE}

    ping -c 3 -w 10 ${IP}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP} failed " && return ${FAILURE}

    iptables -t nat --list --wait | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect iptables rules success after stop container" && return ${FAILURE}

    mount | grep ${netns}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mount grep netns ${netns} ssuccess after stop container" && return ${FAILURE}

    isula rm ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm cont ${cont_name} failed " && return ${FAILURE}

    # run container with network and --rm
    cont_id=$(isula run -tid --net ${network_name} --rm -n ${cont_name} busybox sh)
    [[ "x${cont_id}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont_name} with network ${network_name} ${network_name2} failed" && return ${FAILURE}

    netns=$(isula inspect -f {{.NetworkSettings.SandboxKey}} ${cont_name})
    [[ "x${netns}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect netns failed" && return ${FAILURE}

    test_container_and_kill

    for i in $(seq 1 20); do
        isula ps -a | grep ${cont_name}
        if [ $? -ne 0 ]; then
            break
        fi
        sleep 2
    done

    ping -c 3 -w 10 ${IP}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP} failed " && return ${FAILURE}

    iptables -t nat --list --wait | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect iptables rules success after stop container" && return ${FAILURE}

    mount | grep ${netns}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mount grep netns ${netns} ssuccess after stop container" && return ${FAILURE}

    isula network rm ${network_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm network ${network_name} failed " && return ${FAILURE}

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_restartpolicy_and_networks || ((ans++))

show_result ${ans} "${curr_path}/${0}"
