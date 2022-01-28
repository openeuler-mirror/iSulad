#!/bin/bash
#
# attributes: isula network help
# concurrent: YES
# spend time: 1

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
##- @Create: 2021-01-21
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh

if [ ${enable_native_network} -ne 0 ]; then
    msg_info "${test} disable native network, just ignore test." 
    exit 0
fi

function test_network_help()
{
    local ret=0
    local test="network help test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula network
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula network failed" && ((ret++))

    isula network --help
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula network failed" && ((ret++))

    isula network create --help
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula network create --help failed" && ((ret++))

    isula network inspect --help
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula network inspect --help failed" && ((ret++))

    isula network ls --help
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula network ls --help failed" && ((ret++))
    
    isula network rm --help
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula network rm --help failed" && ((ret++))

    isula network xx 2>&1 | grep "command \"xx\" not found"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula network xx grep failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_network_help || ((ans++))

show_result ${ans} "${curr_path}/${0}"
