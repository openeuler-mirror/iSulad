#!/bin/bash
#
# attributes: isulad basic blkio iops
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

function test_blkio_iops_spec()
{
    local ret=0
    local image="busybox"
    local test="container blkio iops test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -itd --device-read-iops /dev/loop0:-1 $image /bin/sh 2>&1 | grep "Number must be unsigned 64 bytes integer"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check Number must be unsigned 64 bytes integer" && ((ret++))

    isula run -itd --device-write-iops /dev/loop0:-1 $image /bin/sh 2>&1 | grep "Number must be unsigned 64 bytes integer"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check Number must be unsigned 64 bytes integer" && ((ret++))

    isula run -itd --device-write-iops /dev/loop0:2b $image /bin/sh 2>&1 | grep "Number must be unsigned 64 bytes integer"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check Number must be unsigned 64 bytes integer" && ((ret++))

    c_id=`isula run -itd --device-read-iops /dev/loop0:123 --device-read-iops /dev/zero:111 --device-write-iops /dev/loop0:567 --device-write-iops /dev/zero:321 busybox sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/blkio/blkio.throttle.read_iops_device" | grep "7:0 123"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/blkio/blkio.throttle.read_iops_device" | grep "1:5 111"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/blkio/blkio.throttle.write_iops_device" | grep "7:0 567"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/blkio/blkio.throttle.write_iops_device" | grep "1:5 321"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_blkio_iops_spec || ((ans++))

show_result ${ans} "${curr_path}/${0}"
