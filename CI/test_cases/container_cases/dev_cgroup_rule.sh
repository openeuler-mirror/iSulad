#!/bin/bash
#
# attributes: isulad basic device cgroup rule
# concurrent: NA
# spend time: 5

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
##- @Author: lifeng
##- @Create: 2020-09-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_cpu_dev_cgoup_rule_spec()
{
    local ret=0
    local image="busybox"
    local test="container device cgroup rule test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -itd --device-cgroup-rule='b *:*' busybox 2>&1 | grep "Invalid value"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid value" && ((ret++))

    isula run -itd --device-cgroup-rule='d *:*' busybox 2>&1 | grep "Invalid value"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid value" && ((ret++))

    isula run -itd --device-cgroup-rule='d *:* xxx' busybox 2>&1 | grep "Invalid value"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid value" && ((ret++))

    c_id=`isula run -itd --device-cgroup-rule='b 11:22 rmw' --device-cgroup-rule='c *:23 rmw' --device-cgroup-rule='c 33:* rm' busybox sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "b 11:22 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check b 11:22 rmw: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c \*:23 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c *:23 rmw: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c 33:\* rm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c 33:* rm: ${image}" && ((ret++))

    isula restart -t 0 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "b 11:22 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check b 11:22 rmw: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c \*:23 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c *:23 rmw: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c 33:\* rm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c 33:* rm: ${image}" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    c_id=`isula run -itd --device-cgroup-rule='a 11:22 rmw' busybox sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "a \*:\* rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check a *:* rwm: ${image}" && ((ret++))

    isula restart -t 0 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "a \*:\* rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check a *:* rwm: ${image}" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_cpu_dev_cgoup_rule_spec || ((ans++))

show_result ${ans} "${curr_path}/${0}"
