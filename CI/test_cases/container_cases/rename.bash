#!/bin/bash
#
# attributes: isulad basic container hook
# concurrent: NA
# spend time: 5

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
##- @Author: lifeng
##- @Create: 2020-06-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.bash

function test_rename_spec()
{
    local ret=0
    local image="busybox"
    local test="container rename test => (${FUNCNAME[@]})"
    old_name=old_name
    rename_log=/tmp/rename.log

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    CONT=`isula run -n $old_name -itd ${image}`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula rename > $rename_log 2>&1
	[[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check rename container exit code: ${image}" && ((ret++))

    cat $rename_log | grep "requires 2 arguments"
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check error output with image: ${image}" && ((ret++))

    isula rename $old_name $old_name > $rename_log 2>&1
	[[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check rename same container exit code: ${image}" && ((ret++))

    cat $rename_log | grep "Renaming a container with the same name as its current name"
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check error output with image: ${image}" && ((ret++))

    isula rename no_exist no_exist1 > $rename_log 2>&1
	[[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check rename same container exit code: ${image}" && ((ret++))

    cat $rename_log | grep "No such container"
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check error output with image: ${image}" && ((ret++))

    isula rename $old_name 1 > $rename_log 2>&1
	[[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check rename same container exit code: ${image}" && ((ret++))
    
    cat $rename_log | grep "Invalid container new name"
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check error output with image: ${image}" && ((ret++))

    isula rename $old_name 123@ > $rename_log 2>&1
	[[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check rename same container exit code: ${image}" && ((ret++))

    cat $rename_log | grep "Invalid container new name"
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check error output with image: ${image}" && ((ret++))

    isula rename $old_name new_name > $rename_log 2>&1
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check error output with image: ${image}" && ((ret++))

    isula rm -f new_name
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check error output with image: ${image}" && ((ret++))

    rm -f $rename_log

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_rename_spec || ((ans++))

show_result ${ans} "${curr_path}/${0}"