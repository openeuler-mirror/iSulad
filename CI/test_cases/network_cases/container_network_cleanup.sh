#!/bin/bash
#
# attributes: container network cleanup
# concurrent: NA
# spend time: 118

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
##- @Author: zhangxiaoyu
##- @Create: 2021-02-04
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_container_network_cleanup()
{
    local ret=0
    local network_name1="cni1"
    local network_name2="cni2"
    local cont_name="cont_name"

    local test="container network cleanup test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    # create network
    isula network create --subnet 172.20.5.0/24 ${network_name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${network_name1} failed" && return ${FAILURE}

    isula network create --subnet 2001:db8:12::/64 ${network_name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${network_name2} failed" && return ${FAILURE}

    # run container with network
    cont_id=$(isula run -tid --net ${network_name1},${network_name2} -n ${cont_name} busybox sh)
    [[ "x${cont_id}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont_name} with network ${network_name1} ${network_name2} failed" && return ${FAILURE}

    # kill lxc
    pkill lxc-start
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - kill lxc-start failed" && return ${FAILURE}

    for i in $(seq 1 10); do
        status=$(isula inspect -f {{.State.Status}} ${cont_name})
        if [ "x${status}" == "xexited" ]; then
            break;
        fi
        sleep 1
    done
    
    # test iptables rule cleanup
    isula start ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start container ${cont_name} failed" && return ${FAILURE}

    isula stop -t 0 ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop container ${cont_name} failed" && return ${FAILURE}

    iptables -t nat --list | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect iptables rules success after stop container" && return ${FAILURE}

    ip6tables -t nat --list | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ip6tables rules success after stop container" && return ${FAILURE}
    
    isula start ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start container ${cont_name} failed" && return ${FAILURE}

    # stop isulad and kill lxc
    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    pkill lxc-start
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - kill lxc-start failed" && return ${FAILURE}

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    # test iptables rule cleanup
    for i in $(seq 1 10); do
        isula start ${cont_name}
        if [ $? -eq 0 ]; then
            break;
        fi
        sleep 2
    done
    status=$(isula inspect -f {{.State.Status}} ${cont_name})
    [[ "x${status}" != "xrunning" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start container ${cont_name} failed" && return ${FAILURE}

    isula stop -t 0 ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop container ${cont_name} failed" && return ${FAILURE}

    iptables -t nat --list | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect iptables rules success after stop container" && return ${FAILURE}

    ip6tables -t nat --list | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ip6tables rules success after stop container" && return ${FAILURE}

    isula rm ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm ${cont_name} failed" && return ${FAILURE}

    isula network rm ${network_name1} ${network_name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${network_name1} ${network_name2} failed" && return ${FAILURE}

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_container_network_cleanup || ((ans++))

show_result ${ans} "${curr_path}/${0}"
