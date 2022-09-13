#!/bin/bash
#
# attributes: isulad timezone
# concurrent: NA
# spend time: 10

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: zhongtao
##- @Create: 2022-09-13
#######################################################################

source ../helpers.sh
curcnt_timezone=`readlink /etc/localtime`

function do_check_timezone()
{
    ln -sf $1 /etc/localtime
    localtime=`date "+%:z" | sed 's/://g'`

    stop_isulad_with_valgrind
    start_isulad_with_valgrind

    containername="test_timezone"

    isula run --name $containername $2 /bin/sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && return ${FAILURE}

    containertime=`isula inspect -f "{{.State.StartedAt}}" $containername | tail -c 7 | sed 's/://g'`
    fn_check_eq "$localtime" "$containertime" "localtime is $localtime get: $containertime"

    isula rm -f $containername
}

function test_timezone()
{
    local image="busybox"
    local test="container timezone test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && return ${FAILURE}

    do_check_timezone "/usr/share/zoneinfo/Pacific/Kiritimati" "$image"  
    do_check_timezone "/usr/share/zoneinfo/right/Canada/Newfoundland" "$image" 
    do_check_timezone "/usr/share/zoneinfo/Asia/Kolkata" "$image" 
    do_check_timezone "/usr/share/zoneinfo/right/Pacific/Chatham" "$image" 
    do_check_timezone "/usr/share/zoneinfo/Etc/GMT" "$image" 

    ln -sf $curcnt_timezone /etc/localtime

    isula rmi ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image ${image}" && return ${FAILURE}

    stop_isulad_with_valgrind
    start_isulad_with_valgrind

    msg_info "${test} finished with return ${TC_RET_T}..."
    return $TC_RET_T
}

declare -i ans=0

test_timezone || ((ans++))

show_result ${ans} "${curr_path}/${0}"
