#!/bin/bash
#
# attributes: isulad bind special directory
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
##- @Create: 2020-11-27
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_bind_special_dir()
{
    local ret=0
    local runtime=$1
    local image="busybox"
    local test="container bind special directory test with ($runtime) => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    # when create container in container, runc not support to mount /dev
    if [ $runtime == "runc" ]; then
        c_id=`isula run -itd -v -itd --runtime=$runtime -v /sys/fs:/sys/fs:rw,rshared -v /proc:/proc  -v /dev/pts:/dev/pts:rw busybox sh`
    else
        c_id=`isula run --runtime=$runtime -itd -v -itd -v /sys/fs:/sys/fs:rw,rshared -v /proc:/proc -v /dev:/dev:ro -v /dev/pts:/dev/pts:rw busybox sh`
    fi
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "ls -al /sys/fs" | grep "cgroup"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

for element in ${RUNTIME_LIST[@]};
do
    test_bind_special_dir $element || ((ans++))
done

show_result ${ans} "${curr_path}/${0}"
