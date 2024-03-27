#!/bin/bash
#
# attributes: isulad basic cpu realtime
# concurrent: NA

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: huangsong
##- @Create: 2023-01-29
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_cpurt_isulad_abnormal()
{
    local ret=0
    local test="isulad cpu realtime abnormal test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isulad --cpu-rt-period xx --cpu-rt-runtime 950000  2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-period: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-period" && ((ret++))

    isulad --cpu-rt-period 1000000 --cpu-rt-runtime xx  2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-runtime: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-runtime" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_isula_update_normal()
{
    local ret=0
    local image="busybox"
    local test="isulad update cpu realtime normal test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    #start isulad with cpu_rt
    start_isulad_without_valgrind --cpu-rt-period 1000000 --cpu-rt-runtime 950000
    
    c_id=`isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime 1000 --runtime $1 ${image} sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula update --cpu-rt-period 900000 --cpu-rt-runtime 2000 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to update container cpu-rt-runtime" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.rt_runtime_us" | grep "2000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container cpu.rt_runtime_us: 2000" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.rt_period_us" | grep "900000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container cpu.rt_period_us: 900000" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    stop_isulad_without_valgrind
    #set cpu-rt to the initial state
    start_isulad_without_valgrind --cpu-rt-period 1000000 --cpu-rt-runtime 0

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_isula_update_abnormal()
{
    local ret=0
    local image="busybox"
    local test="isulad update cpu realtime abnormal test => (${FUNCNAME[@]})"

    #start isulad with cpu_rt
    isulad --cpu-rt-period 1000000 --cpu-rt-runtime 950000 -l DEBUG > /dev/null 2>&1 &
    wait_isulad_running
    
    c_id=`isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime 1000 --runtime $1 ${image} sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula update --cpu-rt-period 800000 --cpu-rt-runtime 900000 $c_id 2>&1 | grep "Invalid --cpu-rt-runtime: rt runtime cannot be higher than rt period"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to update container cpu-rt-runtime" && ((ret++))

    isula update --cpu-rt-runtime 1000000 $c_id 2>&1 | grep -i "invalid argument"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to update container cpu-rt-runtime" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_kernel_without_cpurt()
{
    local ret=0
    local image="busybox"
    local test="kernel does not support cpu-rt test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isulad --cpu-rt-period 1000000 --cpu-rt-runtime 950000 2>&1 | grep 'Your kernel does not support cgroup rt period'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - kernel does not support cpu-rt, but start isulad with cpu-rt success" && ((ret++))

    start_isulad_with_valgrind

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime 900000 --runtime $1 $image /bin/sh 2>&1 | grep "Your kernel does not support cgroup rt"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - kernel does not support cpu-rt" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_isula_run_abnormal()
{
    local ret=0
    local image="busybox"
    local test="container cpu realtime test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    #start isulad with cpu_rt
    start_isulad_without_valgrind --cpu-rt-period 1000000 --cpu-rt-runtime 950000

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime -1 --runtime $1 $image /bin/sh 2>&1 | grep "failed to write" | grep -i "cpu.rt_runtime_us: Invalid argument"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-runtime" && ((ret++))

    isula run -itd --cpu-rt-period xx --cpu-rt-runtime 10000 --runtime $1 $image /bin/sh 2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-period: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-period" && ((ret++))

    isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime xx --runtime $1 $image /bin/sh 2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-runtime: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-runtime" && ((ret++))

    isula run -itd --cpu-rt-period xx --cpu-rt-runtime xx --runtime $1 $image /bin/sh 2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-period: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-period" && ((ret++))

    isula run -itd --cpu-rt-period -1 --cpu-rt-runtime 10000 --runtime $1 $image /bin/sh 2>&1 | grep "Invalid --cpu-rt-runtime: rt runtime cannot be higher than rt period"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cpu-rt-runtime cannot be higher than cpu-rt-period" && ((ret++))

    isula run -itd --cpu-rt-period 100 --cpu-rt-runtime 10000 --runtime $1 $image /bin/sh 2>&1 | grep "Invalid --cpu-rt-runtime: rt runtime cannot be higher than rt period"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cpu-rt-runtime cannot be higher than cpu-rt-period" && ((ret++))

    isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime 960000 --runtime $1 $image /bin/sh 2>&1 | grep "failed to write" | grep -i "cpu.rt_runtime_us: Invalid argument"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-runtime" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_isula_run_normal()
{
    local ret=0
    local image="busybox"

    isula run -itd -n box --cpu-rt-period 1000000 --cpu-rt-runtime 1000 --runtime $1 $image /bin/sh 2>&1
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container" && ((ret++))

    isula rm -f box
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))
    
    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function do_test()
{
    local ret=0
    local runtime=$1
    local test="cpu_rt_test => (${runtime})"
    msg_info "${test} starting..."

    if [ -f "/sys/fs/cgroup/cpu/cpu.rt_runtime_us" ];then
        test_isula_run_abnormal $runtime|| ((ret++))
        test_isula_run_normal $runtime || ((ret++))
        test_cpurt_isulad_abnormal $runtime || ((ret++))
        test_isula_update_normal $runtime || ((ret++))
        test_isula_update_abnormal $runtime || ((ret++))
        stop_isulad_without_valgrind
        # set cpu-rt to the initial state
        start_isulad_with_valgrind --cpu-rt-period 1000000 --cpu-rt-runtime 0
    else
        test_kernel_without_cpurt $runtime || ((ans++))
    fi

    msg_info "${test} finished with return ${ret}..."

    return ${ret}
}

declare -i ans=0

for element in ${RUNTIME_LIST[@]};
do
    check_valgrind_log

    do_test $element || ((ans++))

    isula rm -f $(isula ps -aq)
done

show_result ${ans} "${curr_path}/${0}"
