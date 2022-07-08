#!/bin/bash
#
# attributes: isulad basic blkio weight
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

function test_blkio_weight_spec()
{
    local ret=0
    local image="busybox"
    local test="container blkio weight test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -itd --blkio-weight 1001 $image /bin/sh 2>&1 | grep "Range of blkio weight is from 10 to 1000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check Range of blkio weight is from 10 to 1000" && ((ret++))

    isula run -itd --blkio-weight -1 $image /bin/sh 2>&1 | grep "Numerical result out of range"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check Range of blkio weight is from 10 to 1000" && ((ret++))

    isula run -itd --blkio-weight-device /dev/zero:1001 $image /bin/sh 2>&1 | grep "Invalid weight for device"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid weight for device" && ((ret++))

    isula run -itd --blkio-weight-device /dev/zero:-1 $image /bin/sh 2>&1 | grep "Invalid weight for device"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid weight for device" && ((ret++))

    c_id=`isula run -itd --blkio-weight 200  ${image} sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/blkio/blkio.weight" | grep "200"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container blkio.weight: 200" && ((ret++))

    isula update --blkio-weight 300 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to update container blkio.weight" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/blkio/blkio.weight" | grep "300"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container blkio.weight: 300" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

if [ -f "/sys/fs/cgroup/blkio/blkio.weight" ];then
    test_blkio_weight_spec || ((ans++))
fi

show_result ${ans} "${curr_path}/${0}"
