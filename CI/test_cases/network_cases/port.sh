#!/bin/bash
#
# attributes: isulad basic port
# concurrent: NA
# spend time: 15

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
##- @Author: haozi007
##- @Create: 2020-12-29
#######################################################################
curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_port()
{
    local ret=0
    local containername=test_create

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula network create cni0
    fn_check_eq "$?" "0" "create network failed"

    isula run -itd --net cni0 -p 8080:80 --name $containername busybox
    fn_check_eq "$?" "0" "create container failed"
    testcontainer $containername running

    isula port $containername | grep "80/tcp -> 0.0.0.0:8080"
    fn_check_eq "$?" "0" "port failed"

    isula inspect -f '{{.NetworkSettings}}' $containername | grep HostPort | grep 8080
    fn_check_eq "$?" "0" "inspect container failed"

    isula rm -f $containername
    fn_check_eq "$?" "0" "rm container failed"

    isula network rm cni0
    fn_check_eq "$?" "0" "rm network failed"

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_port || ((ans++))

show_result ${ans} "${curr_path}/${0}"