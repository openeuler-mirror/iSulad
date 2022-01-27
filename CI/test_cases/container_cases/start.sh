#!/bin/bash
#
# attributes: isulad inheritance start
# concurrent: YES
# spend time: 11

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
##- @Create: 2020-03-30
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh

function do_test_t()
{
    containername=test_start
    isula create -t --name $containername busybox
    fn_check_eq "$?" "0" "create failed"
    testcontainer $containername inited

    isula start $containername
    fn_check_eq "$?" "0" "start failed"
    testcontainer $containername running

    isula stop $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    return $TC_RET_T
}

function do_attach_local_test_t()
{
    local ret=0
    local image="busybox"
    local test="container start with --attach local test => (${FUNCNAME[@]})"

    containername=start_attach
    isula create -ti --name $containername busybox /bin/sh -c 'echo "hello"'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create ${containername}" && ((ret++))
    testcontainer $containername inited

    result=`isula start -a $containername`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start -a ${containername}" && ((ret++))
    testcontainer $containername exited

    isula rm -f $containername
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container" && ((ret++))

    id=`isula create -ti busybox /bin/sh -c 'ech "hello"'`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container" && ((ret++))

    isula start -a $id
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start container success, not as expected:failed" && ((ret++))

    isula rm -f $id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula rm container" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function do_attach_remote_test_t()
{
    local ret=0
    local image="busybox"
    local config='tcp://127.0.0.1:2890'
    local test="container start with --attach remote test => (${FUNCNAME[@]})"

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind -H "$config"

    containername=start_attach
    isula create -ti -H "$config" --name $containername busybox /bin/sh -c 'echo "hello"'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create ${containername} remote" && ((ret++))
    testcontainer $containername inited

    result=`isula start -a -H "$config" $containername`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start -a ${containername} remote" && ((ret++))
    testcontainer $containername exited

    isula rm -f -H "$config" $containername
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container remote" && ((ret++))

    containername=start_exit
    isula run -it -H "$config" --name $containername busybox /bin/sh -c 'exit 5'
    [[ $? -ne 5 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid exit code with remote start" && ((ret++))

    isula start -a -H "$config" $containername
    [[ $? -ne 5 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid exit code with start and attach container remote" && ((ret++))

    isula rm -f -H "$config" $containername
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container" && ((ret++))

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

do_test_t || ((ans++))

do_attach_local_test_t || ((ans++))

do_attach_remote_test_t || ((ans++))

show_result ${ans} "${curr_path}/${0}"
