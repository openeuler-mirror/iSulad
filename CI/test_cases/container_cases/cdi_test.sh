#!/bin/bash
#
# attributes: isulad cdi
# concurrent: NA
# spend time: 41

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: liuxu
##- @Create: 2024-04-16
#######################################################################

source ../helpers.sh
curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/criconfigs)
pause_img_path=$(realpath $curr_path/test_data)
cdi_static_dir="/etc/cdi"

function do_pre()
{
    cp /etc/isulad/daemon.json /etc/isulad/daemon.bak
    sed -i "s#\"pod-sandbox-image\": \"\"#\"pod-sandbox-image\": \"mirrorgooglecontainers/pause-amd64:3.0\"#g" /etc/isulad/daemon.json
    sed -i "/\"cni-conf-dir\": \".*\"/a\ \ \ \ \"enable-cri-v1\": true," /etc/isulad/daemon.json
    sed -i "/\"cni-conf-dir\": \".*\"/a\ \ \ \ \"enable-cdi\": true," /etc/isulad/daemon.json

    check_valgrind_log
    start_isulad_without_valgrind

    isula load -i ${pause_img_path}/pause.tar
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to load pause" && return ${FAILURE}

    isula pull busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull busybox" && return ${FAILURE}

    crictl images | grep "mirrorgooglecontainers/pause-amd64"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to find mirrorgooglecontainers/pause-amd64 image" && return ${FAILURE}

    return 0
}

function do_post()
{
    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    check_valgrind_log
    start_isulad_without_valgrind
}

function verify_injected_vendor0() {
    # check env
    output=$(crictl exec --sync "$1" sh -c 'echo $VENDOR0')
    [[ "$output" != "injected" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - env check failed" && return ${FAILURE}

    # check hooks
    cat /tmp/cdi_hook_test.log | grep "prestart"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - hook check failed" && return ${FAILURE}

    # check mounts
    output=$(crictl exec --sync "$1" sh -c 'stat -c %a /tmp/cdi_mounts_test')
    [[ "$output" != "755" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mount check failed" && return ${FAILURE}

    return 0
}

function verify_injected_loop8() {
    # check env
    output=$(crictl exec --sync "$1" sh -c 'echo $LOOP8')
    [[ "$output" != "CDI8" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - env check failed" && return ${FAILURE}

    # check device nodes
    output=$(crictl exec --sync "$1" sh -c 'stat -c %a /dev/loop8')
    [[ "$output" != "640" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - device nodes check failed" && return ${FAILURE}
    output=$(crictl exec --sync "$1" sh -c 'stat -c %t.%T /dev/loop8')
    [[ "$output" != "7.8" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - device nodes check failed" && return ${FAILURE}
    output=$(crictl exec --sync "$1" sh -c 'stat -c %t.%T /dev/loop8c')
    [[ "$output" != "7.b" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - device nodes check failed" && return ${FAILURE}

    # check mounts
    output=$(crictl exec --sync "$1" sh -c 'stat -c %a /tmp/cdi_mounts_test_loop8')
    [[ "$output" != "755" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mount check failed" && return ${FAILURE}

    return 0
}

function verify_injected_loop9() {
    # check env
    output=$(crictl exec --sync "$1" sh -c 'echo $LOOP9')
    [[ "$output" != "present" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - env check failed" && return ${FAILURE}

    # check device nodes
    output=$(crictl exec --sync "$1" sh -c 'stat -c %a /dev/loop9')
    [[ "$output" != "644" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - device nodes check failed" && return ${FAILURE}
    output=$(crictl exec --sync "$1" sh -c 'stat -c %t.%T /dev/loop9')
    [[ "$output" != "7.9" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - device nodes check failed" && return ${FAILURE}

    return 0
}

function check_full_cdi()
{
    verify_injected_vendor0 $1
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - verify_injected_vendor0 failed" && return ${FAILURE}
    
    verify_injected_loop8 $1
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - verify_injected_loop8 failed" && return ${FAILURE}
    
    verify_injected_loop9 $1
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - verify_injected_loop9 failed" && return ${FAILURE}

    return 0
}

function do_test_help()
{
    msg_info "cdi test starting..."

    isula rm -f `isula ps -a -q`

    sid=`crictl runp ${data_path}/$1`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to run sandbox" && return ${FAILURE}

    cid=`crictl create $sid ${data_path}/$2 ${data_path}/$1`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create container failed" && return ${FAILURE}

    crictl start $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start container failed" && return ${FAILURE}

    crictl stats
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stats container failed" && return ${FAILURE}

    check_full_cdi $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check cdi failed" && return ${FAILURE}

    crictl stop $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop container failed" && return ${FAILURE}

    crictl rm $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm container failed" && return ${FAILURE}

    crictl stopp $sid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop sandbox failed" && return ${FAILURE}

    crictl rmp $sid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm sandbox failed" && return ${FAILURE}

    return 0
}

function do_test_full_cdi()
{
    if [ ! -d "$cdi_static_dir" ]; then
        mkdir -p "$cdi_static_dir"
    fi
    cp -f ${pause_img_path}/cdi_devices.json ${cdi_static_dir}/cdi_devices.json

    mkdir -p /tmp/cdi_mounts_test
    cat  > /tmp/cdi_mounts_test_loop8  << EOF
origin data
EOF
    chmod  755  /tmp/cdi_mounts_test_loop8
    mkdir -p /tmp/cdi_mounts_test_loop9
    
    mknod /dev/loop8 b 7 8
    mknod /dev/loop9 b 7 9
    mknod /dev/loop8c c 7 11

    cat  > /tmp/cdi_printargs.sh  << EOF
#!/bin/bash
echo "\$(date +'%Y-%m-%d %H:%M:%S') Input parameter: \$1 \$2" >> /tmp/cdi_hook_test.log
EOF
    chmod  755  /tmp/cdi_printargs.sh

    do_test_help "sandbox-config.json" "container-config-cdi.json" || ((ans++))

    rm -f /tmp/cdi_printargs.sh
    rm -f /tmp/cdi_hook_test.log
    rm -f /dev/loop8
    rm -f /dev/loop9
    rm -f /dev/loop8c

    rm -f ${cdi_static_dir}/cdi_devices.json
    rm -f /tmp/cdi_printargs
    rmdir /tmp/cdi_mounts_test
    rm -f /tmp/cdi_mounts_test_loop8
    rmdir /tmp/cdi_mounts_test_loop9
    rm -f /tmp/cdi_printargs.sh

    return 0
}

declare -i ans=0

# do_pre || ((ans++))
# do_test_full_cdi || ((ans++))
# do_post

show_result ${ans} "${curr_path}/${0}"
