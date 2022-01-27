#!/bin/bash
#
# attributes: isulad inheritance restart
# concurrent: YES
# spend time: 1

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
##- @Author: gaohuatao
##- @Create: 2020-07-1
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh

function do_pre()
{
    local ret=0

    cp -f /etc/isulad/daemon.json /etc/isulad/daemon.bak
    # delete next line
    sed -i '/    \"dm\.fs\=ext4\"\,/{n;d}' /etc/isulad/daemon.json
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to modify daemon.json" && ((ret++))
    sed -i '/    \"dm\.fs\=ext4\"\,/a\    \"dm\.min\_free\_space\=10\%\"\,\n    \"dm\.basesize\=11G\"' /etc/isulad/daemon.json
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to modify daemon.json" && ((ret++))

    return $ret
}

function test_grow_fs()
{
    local ret=0

    local test="restart isulad specify dm.basesize test => (${FUNCNAME[@]})"
    msg_info "${test} starting..."

    id=`isula run -tid busybox`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container failed" && ((ret++))

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula rm -f $id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm container id:$id failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function do_post()
{
    local ret=0

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    return ${ret}
}

declare -i ans=0

driver_name=$(isula info | grep "Storage Driver" | cut -d " " -f3)
if [[ "x$driver_name" == "xdevicemapper" ]]; then
    do_pre || ((ans++))
    test_grow_fs || ((ans++))
    do_post || ((ans++))
fi

show_result ${ans} "${curr_path}/${0}"
