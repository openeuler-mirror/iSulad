#!/bin/bash
#
# attributes: isulad integration of image basic testcase
# concurrent: NA
# spend time: 4

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
##- @Author: Haozi007
##- @Create: 2020-07-21
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

image="busybox"

function test_image_info() {
    local ret=0
    local uimage="docker.io/library/nats"
    local test="list && inspect image info test => (${FUNCNAME[@]})"
    local lid
    local cid
    local ucid
    local tmp_fname
    local change_file

    msg_info "${test} starting..."

    isula pull ${uimage}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${uimage}" && return "${FAILURE}"

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return "${FAILURE}"

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    lid=$(isula inspect -f '{{.image.top_layer}}' ${image})
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image top layer: ${image}" && ((ret++))

    cid=$(isula create ${image})
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create container failed" && ((ret++))

    ucid=$(isula create ${uimage})
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create container failed" && ((ret++))

    isula run -tid --name checker alpine
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container failed" && ((ret++))

    tmp_fname=$(echo -n "/var/run/isulad/storage" | sha256sum | awk '{print $1}')
    rm -f "${ISULAD_RUN_ROOT_PATH}/storage/${tmp_fname}.json"

    change_file="${ISULAD_ROOT_PATH}/storage/overlay/${lid}/diff/etc/group"
    echo "xxx:11" >> "${change_file}"

    sed -i 's#image-layer-check": false#image-layer-check": true#g' /etc/isulad/daemon.json
    pkill -9 isulad
    start_isulad_with_valgrind

    isula ps -a | grep "${cid}"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - container: ${cid} exist with invalid image" && ((ret++))

    isula ps -a | grep "${ucid}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - container: ${ucid} do not exist with valid image" && ((ret++))

    isula exec -it checker date
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - container: checker exec failed with valid image" && ((ret++))

    isula images | grep busybox
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image: ${image} exist" && ((ret++))

    isula images | grep nats
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - valid image: ${uimage} do not exist" && ((ret++))

    isula rm "${ucid}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - remove container failed" && ((ret++))

    ucid=$(isula run -tid ${uimage})
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container failed" && ((ret++))

    isula stop -t 0 "${ucid}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop container failed" && ((ret++))

    isula rm "${ucid}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - remove container failed" && ((ret++))

    isula rm -f $(isula ps -aq)

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

function pre_test() {
    is_overlay_driver
    if [ $? -ne 0 ]; then
        exit 0
    fi

    check_valgrind_log
    isulad -l debug &
    wait_isulad_running

    isula rmi $(isula images | grep busybox | awk '{print $3}')
}

function post_test() {
    [[ ${ans} -ne 0 ]] && tail -200 "${ISUALD_LOG}"
    sed -i 's#image-layer-check": true#image-layer-check": false#g' /etc/isulad/daemon.json
    check_valgrind_log
    start_isulad_with_valgrind

    isula pull ${image}
}

declare -i ans=0

pre_test

test_image_info || ((ans++))

post_test

show_result "${ans}" "${curr_path}/${0}"
