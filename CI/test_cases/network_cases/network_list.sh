#!/bin/bash
#
# attributes: isulad basic network list
# concurrent: NA
# spend time: 15

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
##- @Create: 2020-10-26
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_network_list()
{
    local ret=0
    local name1="cni1"
    local name2="cni2"
    local invalid="cni3"
    local test="network list test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula network create ${name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name1} failed" && return ${FAILURE}
    file1="/etc/cni/net.d/isulacni-${name1}.conflist"
    [ ! -f ${file1} ] && msg_err "${FUNCNAME[0]}:${LINENO} - file ${file1} not exist" && return ${FAILURE}

    isula network create ${name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name2} failed" && return ${FAILURE}
    file2="/etc/cni/net.d/isulacni-${name2}.conflist"
    [ ! -f ${file2} ] && msg_err "${FUNCNAME[0]}:${LINENO} - file ${file2} not exist" && return ${FAILURE}

    isula network ls ${name1} 2>&1 | grep "\"isula network ls\" requires 0 arguments"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - list network and catch error msg failed" && return ${FAILURE}

    isula network ls -f name=.xx 2>&1 | grep "Unrecognised filter value for name"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - list network and catch error msg failed" && return ${FAILURE}

    isula network ls -f aa=bb 2>&1 | grep "Invalid filter"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - list network and catch error msg failed" && return ${FAILURE}

    isula network ls -q | grep ${name1} 
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - list network --quiet failed" && return ${FAILURE}

    isula network ls -q | grep ${name2} 
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - list network --quiet failed" && return ${FAILURE}

    isula network ls --filter name=${name1} | grep ${name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to ls network ${name1} by filter" && return ${FAILURE}

    isula network ls --filter name=${invalid} | grep ${invalid}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ls network ${invalid} by filter success, but should failed" && return ${FAILURE}

    isula network ls --filter plugin=bridge | grep ${name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to ls network by filter bridge plugin" && return ${FAILURE}

    isula network ls --filter plugin=bridge | grep ${name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to ls network by filter bridge plugin" && return ${FAILURE}

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula network ls --filter plugin=bridge | grep ${name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to ls network by filter bridge plugin after restart isulad" && return ${FAILURE}

    isula network rm ${name1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${name1} failed" && return ${FAILURE}

    isula network rm ${name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - network rm ${name2} failed" && return ${FAILURE}

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_network_list || ((ans++))

show_result ${ans} "${curr_path}/${0}"
