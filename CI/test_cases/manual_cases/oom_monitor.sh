#!/bin/bash
#
# attributes: isulad oom monitor
# concurrent: NA
# spend time: 6

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: jikai
##- @Create: 2024-04-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
test_data_path=$(realpath $curr_path/test_data)

function test_oom_monitor()
{
    local ret=0
    local ubuntu_image="ubuntu"
    local test="container oom monitor test => (${FUNCNAME[@]})"
    containername="oommonitor"

    msg_info "${test} starting..."

    isula pull ${ubuntu_image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${ubuntu_image}" && return ${FAILURE}

    isula images | grep ubuntu
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${ubuntu_image}" && ((ret++))

    # use more than 10m memory limit, otherwise it might fail to run
    # iSulad monitor cgroup file for oom event, however oom triggers cgroup files delete
    # if cgroup files were deleted before oom event was handled for iSulad we might failed to detect oom event
    isula run -it -m 10m --runtime runc --name $containername $ubuntu_image perl -e 'for ($i = 0; $i < 100000000; $i++) { $a .= " " x 1024 }'

    isula inspect -f "{{json .State.OOMKilled}} {{.Name}}" $containername 2>&1 | sed -n '1p' | grep "true"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${ubuntu_image}" && ((ret++))

    isula rm -f $containername

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_oom_monitor || ((ans++))

show_result ${ans} "${curr_path}/${0}"
