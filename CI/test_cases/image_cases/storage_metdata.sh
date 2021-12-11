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

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

do_test_t() {
    local ret=0
    local data_set="LowerDir MergedDir UpperDir WorkDir DeviceId DeviceName DeviceSize"

    id=$(isula run -tid busybox)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container" && return "${FAILURE}"
    testcontainer "$id" running

    cxt=$(isula inspect --format='{{json .GraphDriver.Data}}' "$id")
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to inspect container $id" && return "${FAILURE}"

    for i in ${data_set[@]}; do
        echo "$cxt" | grep "$i"
        [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check $i failed" && ((ret++))
    done

    driver_name=$(isula inspect --format='{{json .GraphDriver.Name}}' "$id")
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get container $id storage driver failed" && ((ret++))

    if ! [[ "${driver_name}" =~ "overlay" ]] && ! [[ "${driver_name}" =~ "devicemapper" ]]; then
        echo "expect GraphDriver Name is overlay or devicemapper, not ${driver_name}"
        ((ret++))
    fi

    isula rm -f "$id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container $id" && ((ret++))

    return "${ret}"
}

declare -i ans=0

do_test_t || ((ans++))

show_result "${ans}" "basic storage metadata"
