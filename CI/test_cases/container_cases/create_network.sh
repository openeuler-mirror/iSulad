#!/bin/bash
#
# attributes: isula network create test
# concurrent: NA
# spend time: 4

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
##- @Author: gaohuatao
##- @Create: 2021-01-04
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_network_param()
{
    local ret=0
    local image="busybox"
    local test="container network create test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    root="`isula info | grep 'iSulad Root Dir' | awk -F ':' '{print $2}'`/engines/lcr"

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    id=`isula create -ti --expose 80-89 -P ${image} /bin/sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container with --expose" && ((ret++))

    grep "80/tcp"  ${root}/${id}/config.v2.json
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check expose port 80/tcp" && ((ret++))

    # Without host port and ip
    id=`isula create -ti -p 80-89 ${image} /bin/sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container with -p" && ((ret++))

    grep "88/tcp"  ${root}/${id}/config.v2.json && grep "89/tcp" ${root}/${id}/hostconfig.json 
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check -p 80-89" && ((ret++))
    
    # Host ports range equal to container ports range
    id=`isula create -ti -p 127.0.0.1:80-82:90-92 ${image} /bin/sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container with -p" && ((ret++))

    grep "91/tcp"  ${root}/${id}/config.v2.json && grep "127.0.0.1" ${root}/${id}/hostconfig.json 
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check -p 127.0.0.1:80-82:90-92" && ((ret++))

    # Host ports range to container single port
    id=`isula create -ti -p 127.0.0.1:80-82:90 ${image} /bin/sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container with -p" && ((ret++))

    grep "90/tcp"  ${root}/${id}/config.v2.json && grep "80-82" ${root}/${id}/hostconfig.json 
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check -p 127.0.0.1:80-82:90-92" && ((ret++))

    # Host ports range not equal to container ports range
    id=`isula create -ti -p 127.0.0.1:80-82:90-93 ${image} /bin/sh`
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create container with -p 127.0.0.1:80-82:90-93 , expect fail" && ((ret++))

    # Invalid format
    id=`isula create -ti -p 127.0.0.1:80-82:%90-93 ${image} /bin/sh`
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create container with -p 127.0.0.1:80-82:%90-93 , expect fail" && ((ret++))

    isula rm -f `isula ps -qa`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm all container failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_network_param || ((ans++))

show_result ${ans} "${curr_path}/${0}"
