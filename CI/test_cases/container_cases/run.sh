#!/bin/bash
#
# attributes: isulad inheritance run
# concurrent: YES
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
##- @Author: lifeng
##- @Create: 2020-03-30
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath "$curr_path"/../data)
source ../helpers.sh

function do_test_t() {
    containername=test_basic_run
    containername2=container_to_join
    isula run --name $containername -td busybox
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    isula run --name $containername -td -v /dev/shm:/dev/shm busybox
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    echo AA > /tmp/test_run_env

    isula run --name $containername -itd --user 100:100 -e AAA=BB -e BAA --env-file /tmp/test_run_env busybox
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    isula run --name $containername -itd --external-rootfs / --read-only none sh
    fn_check_eq "$?" "0" "run container with host rootfs failed"
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    isula run --name $containername -itd --net=host --pid=host --ipc=host --uts=host busybox
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    isula run --name $containername -itd --net=none --pid=none --ipc=none --uts=none busybox
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    isula run --name $containername2 -itd busybox
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername2 running

    isula run --name $containername -itd --net=container:$containername2 --pid=container:$containername2 --ipc=container:$containername2 --uts=container:$containername2 busybox
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    isula stop -t 0 $containername2
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername2 exited

    isula rm $containername2
    fn_check_eq "$?" "0" "rm failed"

    return "$TC_RET_T"
}

function do_run_remote_test_t() {
    local ret=0
    local image="busybox"
    local config='tcp://127.0.0.1:2890'
    local test="container start with --attach remote test => (${FUNCNAME[@]})"

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind -H "$config"

    containername=run_remote

    isula run -ti -H "$config" --name $containername busybox xxx
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed check invalid run ${containername} remote" && ((ret++))
    testcontainer $containername exited
    isula rm -f -H "$config" $containername
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container remote" && ((ret++))

    isula run -ti -H "$config" --name $containername busybox /bin/sh -c 'echo "hello"' | grep hello
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run ${containername} remote" && ((ret++))
    testcontainer $containername exited

    isula rm -f -H "$config" $containername
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container remote" && ((ret++))

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

declare -i ans=0

do_test_t || ((ans++))

do_run_remote_test_t || ((ans++))

show_result "${ans}" "${curr_path}/${0}"
