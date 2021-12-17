#!/bin/bash
#
# attributes: isulad network dnsname
# concurrent: NA
# spend time: 15

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
##- @Create: 2021-01-28
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

if [ ${enable_native_network} -ne 0 ]; then
    msg_info "${test} disable native network, just ignore test." 
    exit 0
fi

function test_network_dnsname()
{
    local ret=0
    local net1="cni1"
    local net2="cni2"
    local cont1="cont1"
    local cont2="cont2"
    local test="network dnsname test => (${FUNCNAME[@]})"

    # TODO: enable dnsname testcase
    # skip dnsname testcase, because of dnsname plugin bug
    return 0

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    # dnsname not exist
    mv /opt/cni/bin/dnsname /opt/cni/bin/dnsname.bak
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mv cni dnsname failed" && return ${FAILURE}

    isula network create ${net1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network create ${net1} failed" && return ${FAILURE}

    isula run -tid --net ${net1} -n ${cont1} busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont1} failed" && return ${FAILURE}

    isula run -tid --net ${net1} -n ${cont2} busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont2} failed" && return ${FAILURE}

    IP1=$(isula inspect -f {{.NetworkSettings.Networks.${net1}.IPAddress}} ${cont1})
    [[ "x${IP1}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get ${cont1} IP failed" && return ${FAILURE}

    IP2=$(isula inspect -f {{.NetworkSettings.Networks.${net1}.IPAddress}} ${cont2})
    [[ "x${IP2}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get ${cont2} IP failed" && return ${FAILURE}

    isula exec -it ${cont1} ping -c 3 -w 10 ${IP2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} in ${cont1} failed" && return ${FAILURE}

    isula exec -it ${cont2} ping -c 3 -w 10 ${IP1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} in ${cont2} failed" && return ${FAILURE}

    isula exec -it ${cont1} ping -c 3 -w 10 ${cont2}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${cont2} name in ${cont1} success, but should failed" && return ${FAILURE}

    isula exec -it ${cont2} ping -c 3 -w 10 ${cont1}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${cont1} name in ${cont2} success, but should failed" && return ${FAILURE}

    isula rm -f ${cont1} ${cont2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm -f ${cont1} ${cont2} failed" && return ${FAILURE}

    # dnsname exist
    mv /opt/cni/bin/dnsname.bak /opt/cni/bin/dnsname
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mv cni dnsname failed" && return ${FAILURE}

    isula network create ${net2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network create ${net2} failed" && return ${FAILURE}

    isula run -tid --net ${net2} -n ${cont1} busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont1} failed" && return ${FAILURE}

    isula run -tid --net ${net2} -n ${cont2} busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container ${cont2} failed" && return ${FAILURE}

    IP1=$(isula inspect -f {{.NetworkSettings.Networks.${net2}.IPAddress}} ${cont1})
    [[ "x${IP1}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get ${cont1} IP failed" && return ${FAILURE}

    IP2=$(isula inspect -f {{.NetworkSettings.Networks.${net2}.IPAddress}} ${cont2})
    [[ "x${IP2}" == "x" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get ${cont2} IP failed" && return ${FAILURE}

    isula exec -it ${cont1} ping -c 3 -w 10 ${IP2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP2} in ${cont1} failed" && return ${FAILURE}

    isula exec -it ${cont2} ping -c 3 -w 10 ${IP1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${IP1} in ${cont2} failed" && return ${FAILURE}

    isula exec -it ${cont1} ping -c 3 -w 10 ${cont2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${cont2} name in ${cont1} failed" && return ${FAILURE}

    isula exec -it ${cont2} ping -c 3 -w 10 ${cont1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping ${cont1} name in ${cont2} failed" && return ${FAILURE}

    isula rm -f ${cont1} ${cont2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm -f ${cont1} ${cont2} failed" && return ${FAILURE}

    isula network rm ${net1} ${net2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${net1} ${net2} failed" && return ${FAILURE}

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_network_dnsname || ((ans++))

show_result ${ans} "${curr_path}/${0}"
