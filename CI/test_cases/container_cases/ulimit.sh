#!/bin/bash
#
# attributes: isulad inheritance restart
# concurrent: YES
# spend time: 18

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

function test_ulimit()
{
    local ret=0
    local image="busybox"
    ulimitlog=/tmp/ulimit.log

    local test="ulimit test => (${FUNCNAME[@]})"
    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind --default-ulimit nproc=2048:4096 --default-ulimit nproc=2048:8192 --default-ulimit nofile=1024:4096
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula run --ulimit nproc= $image /bin/sh > $ulimitlog 2>&1
    cat $ulimitlog | grep "delimiter '=' can't be the first or the last character"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula run --ulimit nproc=1024: $image /bin/sh > $ulimitlog 2>&1
    cat $ulimitlog | grep "delimiter ':' can't be the first or the last character"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula run --ulimit npro=1024:2048 $image /bin/sh > $ulimitlog 2>&1
    cat $ulimitlog | grep "Invalid ulimit type"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula run --ulimit nproc=4096:2048 $image /bin/sh > $ulimitlog 2>&1
    cat $ulimitlog | grep "Ulimit soft limit must be less than or equal to hard limit"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula run --ulimit nproc=2048:4096.5 $image /bin/sh > $ulimitlog 2>&1
    cat $ulimitlog | grep "Invalid ulimit hard value"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula run --ulimit nproc==2048:4096 $image /bin/sh > $ulimitlog 2>&1
    cat $ulimitlog | grep "Invalid ulimit argument"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula run --ulimit nproc=2048::4096 $image /bin/sh > $ulimitlog 2>&1
    cat $ulimitlog | grep "Too many limit value arguments"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    container_name="ulimit_test"

    isula run -td -n $container_name --ulimit nofile=20480:40960 --ulimit core=1024:2048 $image /bin/sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))
    
    isula exec $container_name /bin/sh -c "cat /proc/self/limits" | grep "Max open files" |awk '{ print $(NF-1) }' |grep 40960
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula exec $container_name /bin/sh -c "cat /proc/self/limits" | grep "Max open files" |awk '{ print $(NF-2) }' |grep 20480
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula exec $container_name /bin/sh -c "cat /proc/self/limits" | grep "Max processes" |awk '{ print $(NF-1) }' |grep 8192
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula exec $container_name /bin/sh -c "cat /proc/self/limits" | grep "Max processes" |awk '{ print $(NF-2) }' |grep 2048
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula exec $container_name /bin/sh -c "cat /proc/self/limits" | grep "Max core file size" |awk '{ print $(NF-1) }' |grep 4
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula exec $container_name /bin/sh -c "cat /proc/self/limits" | grep "Max core file size" |awk '{ print $(NF-2) }' |grep 2
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    isula rm -f $container_name
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check failed" && ((ret++))

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    rm -rf $ulimitlog

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_ulimit || ((ans++))

show_result ${ans} "${curr_path}/${0}"
