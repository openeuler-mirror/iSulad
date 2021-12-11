#!/bin/bash
#
# attributes: isulad basic image
# concurrent: NA
# spend time: 22

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
##- @Create: 2020-10-12
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
base_image="${curr_path}/busybox.tar"
multiplex_image="${curr_path}/multiplex_busybox.tar"

function test_multiplex_layers_image_load() {
    local ret=0
    local test="isula load image with multiplex layers test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    # remove all images related to busybox
    isula rmi $(isula images | grep busybox | awk '{print $3}')

    # load image lacking layers
    isula load -i "$multiplex_image"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load image success, expect fail: ${multiplex_image}" && ((ret++))

    isula images | grep "multiplex_busybox"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get image: multiplex_busybox, expect no such image" && ((ret++))

    # load base image
    isula load -i "$base_image"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load image failed: ${base_image} with" && ((ret++))

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list base image: busybox" && ((ret++))

    # load image with base image loaded
    isula load -i "$multiplex_image"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load image failed: ${multiplex_image}" && ((ret++))

    container_name=multiplex_container
    isula run -tid --name $container_name multiplex_busybox:latest /bin/sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula run failed" && ((ret++))

    isula exec $container_name sh -c 'ls /gao'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - no such file /gao" && ((ret++))

    isula rm -f $container_name
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm container failed" && ((ret++))

    base_id=$(isula inspect -f '{{.image.id}}' busybox:latest)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to inspect image: busybox:latest" && ((ret++))

    mult_id=$(isula inspect -f '{{.image.id}}' multiplex_busybox:latest)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to inspect image: multiplex_busybox:latest" && ((ret++))

    isula rmi "$base_id" "$mult_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image ${base_id} and ${mult_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

declare -i ans=0

test_multiplex_layers_image_load || ((ans++))

show_result "${ans}" "${curr_path}/${0}"
