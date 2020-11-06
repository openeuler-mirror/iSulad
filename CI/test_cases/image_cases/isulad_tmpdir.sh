#!/bin/bash
#
# attributes: isulad basic container hook
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
##- @Author: gaohuatao
##- @Create: 2020-11-05
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
busybox_image="${curr_path}/busybox.tar"
image_name="busybox:latest"

function restart_isulad()
{
    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

}

function load_pull_test()
{
    isula load -i $busybox_image
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load image failed: ${busybox_image} with" && ((ret++))

    isula rmi $image_name

    isula pull ${image_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image_name}" && return ${FAILURE}
}

function test_isulad_tmpdir()
{
    local ret=0
    local test="ISULAD_TMPDIR env test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."
    isula rm -f `isula ps -qa`
    isula rmi `isula images | awk '{if (NR>1){print $3}}'`

    # The scene of ISULAD_TMPDIR dir is not exists
    export ISULAD_TMPDIR="/var/isula/tmp"
    restart_isulad
    load_pull_test
    test -d /var/isula/tmp/isula-image
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula-image not exist in ISULAD_TMPDIR" && ((ret++))

    # The scene of ISULAD_TMPDIR dir is symbol link that it refers to dir exists
    rm -rf /var/isula/tmp
    mkdir -p /var/tmpdir
    ln -sf /var/tmpdir /var/isula/tmpdir
    unset ISULAD_TMPDIR
    export ISULAD_TMPDIR="/var/isula/tmpdir"
    restart_isulad
    load_pull_test
    test -d /var/isula/tmpdir/isula-image
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula-image not exist in ISULAD_TMPDIR" && ((ret++))

    # rm dest dir of symbol link
    rm -rf /var/tmpdir
    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    # default no ISULAD_TMPDIR env
    unset ISULAD_TMPDIR
    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    load_pull_test
    test -d /var/tmp/isula-image
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula-image not exist in /var/tmp" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_isulad_tmpdir || ((ans++))

show_result ${ans} "${curr_path}/${0}"
