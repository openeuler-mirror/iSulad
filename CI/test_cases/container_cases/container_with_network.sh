#!/bin/bash
#
# attributes: container with networks
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
##- @Create: 2020-12-30
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function ping_ipv6_address()
{
    local ipv6=$1

    for i in `seq 1 3`
    do
        ping6 -c 3 -w 10 ${ipv6}
        if [ $? -eq 0 ]; then
            return 0;
        fi
        sleep 5
    done

    ping6 -c 3 -w 10 ${ipv6}
    return $?
}

function test_container_with_networks()
{
    local ret=0
    local network_name1="cni1"
    local network_name2="cni2"
    local cont_name="cont_name"

    local test="container with networks test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula network create --subnet 172.20.5.0/24 ${network_name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${network_name1} failed" && return ${FAILURE}

    isula network create --subnet 2001:db8:12::/64 ${network_name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${network_name2} failed" && return ${FAILURE}

    cont_id=$(isula run -tid --net ${network_name1},${network_name2} -n ${cont_name} busybox sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont_name} with network ${network_name1} ${network_name2} failed" && return ${FAILURE}

    IP1=$(isula inspect -f '{{json .NetworkSettings.Networks.'${network_name1}'.IPAddress }}' ${cont_name} | sed 's/\"//g')
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ${cont_name} ${network_name1} IP failed " && return ${FAILURE}

    IP2=$(isula inspect -f '{{json .NetworkSettings.Networks.'${network_name2}'.IPAddress }}' ${cont_name} | sed 's/\"//g')
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ${cont_name} ${network_name2} IP failed " && return ${FAILURE}

    ping -c 3 -w 10 ${IP1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} failed " && return ${FAILURE}

    ping_ipv6_address ${IP2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} failed " && return ${FAILURE}

    isula start ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start running ${cont_name} failed " && return ${FAILURE}

    ping -c 3 -w 10 ${IP1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} failed " && return ${FAILURE}

    ping_ipv6_address ${IP2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} failed " && return ${FAILURE}

    isula stop ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop ${cont_name} failed " && return ${FAILURE}

    isula inspect -f '{{json .NetworkSettings.Networks}}' ${cont_name} | grep "{}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect exited ${cont_name} networks failed " && return ${FAILURE}

    ping -c 3 -w 10 ${IP1}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} success, but should failed " && return ${FAILURE}

    ping6 -c 3 -w 10 ${IP2}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} success, but should failed " && return ${FAILURE}

    isula stop ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop exited ${cont_name} failed " && return ${FAILURE}

    isula start ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start exited ${cont_name} failed " && return ${FAILURE}

    IP1=$(isula inspect -f '{{json .NetworkSettings.Networks.'${network_name1}'.IPAddress }}' ${cont_name} | sed 's/\"//g')
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ${cont_name} ${network_name1} IP failed " && return ${FAILURE}

    IP2=$(isula inspect -f '{{json .NetworkSettings.Networks.'${network_name2}'.IPAddress }}' ${cont_name} | sed 's/\"//g')
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ${cont_name} ${network_name2} IP failed " && return ${FAILURE}

    ping -c 3 -w 10 ${IP1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} failed " && return ${FAILURE}

    ping_ipv6_address ${IP2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} failed " && return ${FAILURE}

    isula restart ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - restart running ${cont_name} failed " && return ${FAILURE}

    IP1=$(isula inspect -f '{{json .NetworkSettings.Networks.'${network_name1}'.IPAddress }}' ${cont_name} | sed 's/\"//g')
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ${cont_name} ${network_name1} IP failed " && return ${FAILURE}

    IP2=$(isula inspect -f '{{json .NetworkSettings.Networks.'${network_name2}'.IPAddress }}' ${cont_name} | sed 's/\"//g')
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ${cont_name} ${network_name2} IP failed " && return ${FAILURE}

    ping -c 3 -w 10 ${IP1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} failed " && return ${FAILURE}

    ping_ipv6_address ${IP2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} failed " && return ${FAILURE}

    isula rm ${cont_name}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm running ${cont_name} success, but should failed" && return ${FAILURE}

    ping -c 3 -w 10 ${IP1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} failed " && return ${FAILURE}

    ping_ipv6_address ${IP2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} failed " && return ${FAILURE}

    isula rm -f ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm -f ${cont_name} failed" && return ${FAILURE}

    ping -c 3 -w 10 ${IP1}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} success, but should failed " && return ${FAILURE}

    ping6 -c 3 -w 10 ${IP2}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} success, but should failed " && return ${FAILURE}

    # run container with specify IPv4
    isula run -tid --net ${network_name1} --ip ${IP1} -n ${cont_name} busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont_name} with network ${network_name1} and IP ${IP1} failed" && return ${FAILURE}

    ping -c 3 -w 10 ${IP1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} failed " && return ${FAILURE}

    isula rm -f ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm -f ${cont_name} failed" && return ${FAILURE}

    ping -c 3 -w 10 ${IP1}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} success, but should failed " && return ${FAILURE}

    # run container with specify IPv6
    isula run -tid --net ${network_name2} --ip ${IP2} -n ${cont_name} busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont_name} with network ${network_name2} and IP ${IP2} failed" && return ${FAILURE}

    ping_ipv6_address ${IP2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} failed " && return ${FAILURE}

    isula rm -f ${cont_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm -f ${cont_name} failed" && return ${FAILURE}

    ping6 -c 3 -w 10 ${IP2}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} success, but should failed " && return ${FAILURE}

    bridge1=$(isula network inspect -f {{.plugins.bridge}} ${network_name1})
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get ${network_name1} bridge interface failed" && return ${FAILURE}

    bridge2=$(isula network inspect -f {{.plugins.bridge}} ${network_name2})
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get ${network_name2} bridge interface failed" && return ${FAILURE}

    isula network rm ${network_name1} ${network_name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${network_name1} ${network_name2} failed" && return ${FAILURE}

    iptables -t nat --list | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect iptables rules success after rm container" && return ${FAILURE}

    ip6tables -t nat --list | grep ${cont_id}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ip6tables rules success after rm container" && return ${FAILURE}

    ip link show | grep ${bridge1}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ${bridge1} success after rm container" && return ${FAILURE}

    ip link show | grep ${bridge2}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect ${bridge2} success after rm container" && return ${FAILURE}

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_container_with_networks || ((ans++))

show_result ${ans} "${curr_path}/${0}"
