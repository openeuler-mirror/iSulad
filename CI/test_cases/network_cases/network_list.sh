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

    file1=$(isula network create ${name1} | awk 'END {print}')
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name1} failed" && return ${FAILURE}
    [ ! -f ${file1} ] && msg_err "${FUNCNAME[0]}:${LINENO} - file ${file1} not exist" && return ${FAILURE}

    file2=$(isula network create ${name2} | awk 'END {print}')
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name2} failed" && return ${FAILURE}
    [ ! -f ${file2} ] && msg_err "${FUNCNAME[0]}:${LINENO} - file ${file2} not exist" && return ${FAILURE}

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

    rm -f ${file1}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm ${file1} failed" && return ${FAILURE}

    rm -f ${file2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm ${file2} failed" && return ${FAILURE}

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
