#!/bin/bash
#
# attributes: setup network failed
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
    local invalid_network="invalid"
    local cont_name="cont_name"

    local test="setup network failed test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    # create network
    isula network create --subnet 192.168.25.0/24 ${network_name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${network_name1} failed" && return ${FAILURE}

    isula network create --subnet 192.168.26.0/24 ${network_name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${network_name2} failed" && return ${FAILURE}

    cp ./config/isulacni-invalid.conflist /etc/cni/net.d/

    # restart isulad
    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    # run container
    isula run -tid --net ${network_name1},${invalid_network},${network_name2} -n ${cont_name} busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with network ${network_name1},${invalid_network},${network_name2} success, but should failed" && return ${FAILURE}
    
    # inspect
    isula inspect -f {{.NetworkSettings}} ${cont_name} | grep -E "${network_name1}|${invalid_network}|${network_name2}"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect container network info success, but should failed" && return ${FAILURE}

    ls /var/lib/cni/networks/${network_name1} | grep "192.168"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network ${network_name1} allocate IP" && return ${FAILURE}

    ls /var/lib/cni/networks/${network_name2} | grep "192.168"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network ${network_name2} allocate IP" && return ${FAILURE}

    cont_id=$(isula inspect -f {{.Id}} ${cont_name})

    iptables -t nat --list --wait | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - iptables rule exist" && return ${FAILURE}

    ls /var/lib/cni/results/ | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - CNI execute result rule exist" && return ${FAILURE}

    isula rm $(isula ps -aq)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm containers failed" && return ${FAILURE}

    isula network rm ${network_name1} ${network_name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${network_name1} ${network_name2} failed" && return ${FAILURE}

    rm /etc/cni/net.d/isulacni-invalid.conflist
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm file isulacni-invalid.conflist failed" && return ${FAILURE}

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
