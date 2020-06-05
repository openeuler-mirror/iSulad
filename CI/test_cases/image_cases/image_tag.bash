#!/bin/bash
#
# attributes: isulad inheritance tag
# concurrent: YES
# spend time: 59

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
##- @Author: jikui
##- @Create: 2020-05-05
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.bash

image_busybox="busybox"
image_ubuntu="ubuntu"

function test_tag_image()
{
    local ret=0
    local test="tag image test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull $image_busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image_busybox}" && ((ret++))

    isula pull $image_ubuntu
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image_ubuntu}" && ((ret++))

    isula tag $image_busybox "aaa"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to tag image: ${image_busybox}" && ((ret++))

    isula inspect -f '{{json .image.repo_tags}}' $image_busybox|grep "aaa" >/dev/null 2>&1
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to inspect image: ${image_busybox}" && ((ret++))

    isula tag "image_not_exist" "aaa" >/dev/null 2>&1
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - image tag should failed: ${image_busybox}" && ((ret++))

    isula tag $image_busybox "aaa:bbb"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to tag image: ${image_busybox}" && ((ret++))

    isula inspect -f '{{json .image.repo_tags}}' $image_busybox|grep "aaa:bbb"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to inspect image: ${image_busybox}" && ((ret++))

    local ID_first=`isula inspect -f '{{json .image.id}}' $image_busybox`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to inspect image: ${image_busybox}" && ((ret++))

    local ID_second=`isula inspect -f '{{json .image.id}}' $image_ubuntu`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to inspect image: ${image_ubuntu}" && ((ret++))

    isula tag $image_busybox "ccc"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to tag image: ${image_busybox}" && ((ret++))

    local ID_before=`isula inspect -f '{{json .image.id}}' "ccc"`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to inspect image: ${image_busybox}" && ((ret++))

    isula tag $image_ubuntu "ddd"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to tag image: ${image_ubuntu}" && ((ret++))

    local ID_after=`isula inspect -f '{{json .image.id}}' "ddd"`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to inspect image: ${image_ubuntu}" && ((ret++))

    [[ $ID_first != $ID_before ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to change ID: ${image_busybox}" && ((ret++))
    [[ $ID_second != $ID_after ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to change ID: ${image_ubuntu}" && ((ret++))

    isula rmi  "aaa"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image: ${image_busybox}" && ((ret++))

    isula rmi  "aaa:bbb"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image: ${image_busybox}" && ((ret++))

    isula rmi "ccc"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image: ${image_busybox}" && ((ret++))

    isula rmi "ddd"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image: ${image_ubuntu}" && ((ret++))

    local ID_image_busybox=${ID_first:1:10}

    isula tag $image_ubuntu $image_busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to tag image ${image_ubuntu} with tag ${image_busybox}" && ((ret++))

    isula inspect -f '{{json .image.repo_tags}}' $image_ubuntu|grep $image_busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to inspect image: ${image_ubuntu}" && ((ret++))

    isula rmi $ID_image_busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image: ${ID_image_busybox}" && ((ret++))

    isula rmi ${image_busybox}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image: ${image_busybox}" && ((ret++))

    isula rmi ${image_ubuntu}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image: ${image_ubuntu}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_tag_image || ((ans++))

show_result ${ans} "${curr_path}/${0}"
