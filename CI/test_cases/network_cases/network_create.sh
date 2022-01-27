#!/bin/bash
#
# attributes: isulad basic network create
# concurrent: NA
# spend time: 15

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
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
##- @Create: 2020-09-27
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

if [ ${enable_native_network} -ne 0 ]; then
    msg_info "${test} disable native network, just ignore test." 
    exit 0
fi

function test_network_create()
{
    local ret=0
    local name1="cni1"
    local name2="cni2"
    local name3="a"
    for i in $(seq 1 7);do
        name3=${name3}${name3}
    done
    local name4=${name3}b
    local invalid_name=".xx"
    local test="network create test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula network create ${name1} ${name2} 2>&1 | grep "at most 1 network name"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create networks success, but should failed" && return ${FAILURE}

    isula network create ${name3}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name3} failed" && return ${FAILURE}

    isula network rm ${name3}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${name} failed" && return ${FAILURE}

    isula network create ${name4} 2>&1 | grep "too long"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name4} and catch error msg failed" && return ${FAILURE}

    isula network create ${invalid_name} 2>&1 | grep "Invalid network name"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${invalid_name} success, but should failed" && return ${FAILURE}

    isula network create -d macvlan 2>&1 | grep "Cannot support driver"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network success with unsupported driver macvlan, but should failed" && return ${FAILURE}

    isula network create --gateway 192.172.58.1 2>&1 | grep "Cannot specify gateway without subnet"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network success by specifing gateway without subnet, but should failed" && return ${FAILURE}

    isula network create --subnet 192.172.58.0/33 2>&1 | grep "Invalid subnet"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network success by specifing invalid subnet, but should failed" && return ${FAILURE}

    isula network create --subnet 192.172.58.0/24 --gateway 192.0.1 2>&1 | grep "Invalid gateway"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network success by specifing invalid gateway, but should failed" && return ${FAILURE}

    isula network create --subnet 192.172.58.0/24 --gateway 192.0.0.1 2>&1 | grep "not match"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network success by specifing unmatch subnet gateway, but should failed" && return ${FAILURE}

    isula network create --subnet 192.172.58.156/24 ${name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name1} failed" && return ${FAILURE}
    file1="/etc/cni/net.d/isulacni-${name1}.conflist"
    [ ! -f ${file1} ] && msg_err "${FUNCNAME[0]}:${LINENO} - file ${file1} not exist" && return ${FAILURE}

    isula network create ${name1} 2>&1 | grep "has been used"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name1} success, but should failed" && return ${FAILURE}

    isula network create --subnet 192.172.58.0/24 2>&1 | grep "conflict with CNI config or host network"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network success by specifing conflict subnet, but should failed" && return ${FAILURE}

    cat ${file1} | grep '"subnet": "192.172.58.0/24"'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - no specified subnet in file" && return ${FAILURE}

    cat ${file1} | grep '"gateway": "192.172.58.1"'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - no gateway in file" && return ${FAILURE}

    cat ${file1} | grep '"name": "'${name1}'"'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - no specified name in file" && return ${FAILURE}

    cat ${file1} | grep '"isGateway": true'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - no isGateway in file" && return ${FAILURE}

    cat ${file1} | grep '"ipMasq": true'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - no ipMasq in file" && return ${FAILURE}

    isula network rm ${name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${name1} failed" && return ${FAILURE}

    name=$(isula network create -d bridge --internal | awk 'END {print}')
    [[ "x${name}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network with specifing bridge failed" && return ${FAILURE}

    file="/etc/cni/net.d/isulacni-${name}.conflist"
    cat ${file} | grep '"isGateway": true'
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - find isGateway in file, but should not" && return ${FAILURE}

    cat ${file} | grep '"ipMasq": true'
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - find ipMasq in file, but should not" && return ${FAILURE}

    isula network rm ${name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${name} failed" && return ${FAILURE}

    name=$(isula network create --subnet fff0:0003::0003/64 | awk 'END {print}')
    [[ "x${name}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network with specifing IPv6 subnet" && return ${FAILURE}

    file="/etc/cni/net.d/isulacni-${name}.conflist"
    cat ${file} | grep '"subnet": "fff0:3::/64",'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - no specified subnet in file" && return ${FAILURE}

    cat ${file} | grep '"gateway": "fff0:3::1"'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - no gateway in file" && return ${FAILURE}

    isula network rm ${name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${name} failed" && return ${FAILURE}

    mv /opt/cni/bin/ /opt/cni/bin.bak
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mv cni plugin failed" && return ${FAILURE}

    isula network create 2>&1 | grep "WARN:cannot find cni plugin"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network create detect cni plugin failed" && return ${FAILURE}

    mv /opt/cni/bin.bak /opt/cni/bin
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mv cni plugin failed" && return ${FAILURE}

    isula network rm $(isula network ls -q)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - clean network failed" && return ${FAILURE}

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_network_create || ((ans++))

show_result ${ans} "${curr_path}/${0}"
