#!/bin/bash
#
# attributes: isulad basic network remove
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
##- @Create: 2020-11-27
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_network_remove()
{
    local ret=0
    local name1="cni1"
    local name2="cni2"
    local invalid="cni3"
    local test="network remove test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula network create ${name1} | awk 'END {print}'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name1} failed" && return ${FAILURE}
    file1="/etc/cni/net.d/isulacni-${name1}.conflist"
    [ ! -f ${file1} ] && msg_err "${FUNCNAME[0]}:${LINENO} - file ${file1} not exist" && return ${FAILURE}

    isula network create ${name2} | awk 'END {print}'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create network ${name2} failed" && return ${FAILURE}
    file2="/etc/cni/net.d/isulacni-${name2}.conflist"
    [ ! -f ${file2} ] && msg_err "${FUNCNAME[0]}:${LINENO} - file ${file2} not exist" && return ${FAILURE}

    isula network rm ${invalid} 2>&1 | grep "Cannot find network ${invalid}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cannot catch msg when remove invalid network ${invalid}" && return ${FAILURE}

    isula network rm ${name1} ${name2}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - remove network ${name1} ${name2} failed" && return ${FAILURE}
    test -f ${file1} && msg_err "${FUNCNAME[0]}:${LINENO} - file ${file1} exist" && return ${FAILURE}
    test -f ${file2} && msg_err "${FUNCNAME[0]}:${LINENO} - file ${file2} exist" && return ${FAILURE}

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_network_remove || ((ans++))

show_result ${ans} "${curr_path}/${0}"
