#!/bin/bash
#
# attributes: isulad inheritance version
# concurrent: YES
# spend time: 1

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
##- @Create: 2020-05-04
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath "$curr_path"/../data)
driver="overlay2"
source ../helpers.sh

function pre_test() {
    cut_output_lines isula info
    fn_check_eq "$?" "0" "check failed"

    for i in ${lines[@]}; do
        echo "$i" | grep 'devicemapper'
        if [ $? -eq 0 ]; then
            driver="devicemapper"
        fi
    done
}

function overlay2_status() {
    local ret=0
    local test="isula status overlay2 test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    [[ "${lines[6]}" != "Storage Driver:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Storage Driver failed" && ((ret++))
    [[ "${lines[7]}" != " Backing Filesystem:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Backing Filesystem failed" && ((ret++))
    [[ "${lines[8]}" != " Supports d_type:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Supports d_type failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

function devicemapper_status() {
    local ret=0
    local test="isula status devicemapper test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    [[ "${lines[6]}" != "Storage Driver:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Storage Driver failed" && ((ret++))
    [[ "${lines[7]}" != " Pool Name:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Pool Name failed" && ((ret++))
    [[ "${lines[8]}" != " Pool Blocksize:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Pool Blocksize failed" && ((ret++))
    [[ "${lines[9]}" != " Base Device Size:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Base Device Size failed" && ((ret++))
    [[ "${lines[10]}" != " Backing Filesystem:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Backing Filesystem failed" && ((ret++))
    [[ "${lines[11]}" != " Data file:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Data file failed" && ((ret++))
    [[ "${lines[12]}" != " Metadata file:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Metadata file failed" && ((ret++))
    [[ "${lines[13]}" != " Data Space Used:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Data Space Used failed" && ((ret++))
    [[ "${lines[14]}" != " Data Space Total:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Data Space Total failed" && ((ret++))
    [[ "${lines[15]}" != " Data Space Available:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Data Space Available failed" && ((ret++))
    [[ "${lines[16]}" != " Metadata Space Used:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Metadata Space Used failed" && ((ret++))
    [[ "${lines[17]}" != " Metadata Space Total:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Metadata Space Total failed" && ((ret++))
    [[ "${lines[18]}" != " Metadata Space Available:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Metadata Space Available failed" && ((ret++))
    [[ "${lines[19]}" != " Thin Pool Minimum Free Space:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Thin Pool Minimum Free Space failed" && ((ret++))
    [[ "${lines[20]}" != " Udev Sync Supported:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Udev Sync Supported failed" && ((ret++))
    [[ "${lines[21]}" != " Deferred Removal Enabled:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Deferred Removal Enabled failed" && ((ret++))
    [[ "${lines[22]}" != " Deferred Deletion Enabled:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Deferred Deletion Enabled failed" && ((ret++))
    [[ "${lines[23]}" != " Deferred Deleted Device Count:"* ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula info check Deferred Deleted Enabled failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

function do_test_t() {
    local ret=0

    pre_test
    if [[ "$driver"x = "overlay2"x ]]; then
        overlay2_status || ((ret++))
    elif [[ "$driver"x = "devicemapper"x ]]; then
        devicemapper_status || ((ret++))
    else
        echo "error: not support $driver"
        ((ret++))
    fi

    return "$ret"
}

declare -i ans=0

do_test_t || ((ans++))

show_result "${ans}" "${curr_path}/${0}"
