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

function test_cpu_rt_isulad_spec()
{
    local ret=0
    local test="isulad cpu realtime test => (${FUNCNAME[@]})"

     msg_info "${test} starting..."

    isulad --cpu-rt-period xx --cpu-rt-runtime 950000 /bin/sh 2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-period: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-period" && ((ret++))

    isulad --cpu-rt-period 1000000 --cpu-rt-runtime xx /bin/sh 2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-runtime: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-runtime" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_cpu_rt_isula_spec()
{
    local ret=0
    local image="busybox"
    local test="container cpu realtime test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    #start isulad without cpu_rt
    start_isulad_without_valgrind

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    test_isula_run_spec

    #start isulad without cpu_rt:isulad cpu.rt_period_us default value is the cpu.rt_period_us of the upper-layer directory,cpu.rt_runtime_us is 0.
    isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime 10000 $image /bin/sh 2>&1 | grep "failed to write 10000" | grep "cpu.rt_runtime_us: Invalid argument"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-runtime" && ((ret++))

    stop_isulad_without_valgrind

    #start isulad with cpu_rt
    isulad --cpu-rt-period 1000000 --cpu-rt-runtime 950000 -l DEBUG > /dev/null 2>&1 &
    wait_isulad_running

    test_isula_run_spec
    
    c_id=`isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime 950000  ${image} sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula update --cpu-rt-runtime 90000 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to update container cpu-rt-runtime" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.rt_runtime_us" | grep "90000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container cpu.rt_runtime_us: 90000" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_kernel_without_cpu_rt_spec()
{
    local ret=0
    local image="busybox"
    local test="kernel does not support cpu-rt test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isulad --cpu-rt-period 1000000 --cpu-rt-runtime 950000 -l DEBUG > /dev/null 2>&1 &
    wait_isulad_running

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime 900000 $image /bin/sh 2>&1 | grep "Your kernel does not support cgroup rt"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - kernel does not support cpu-rt" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_isula_run_spec()
{
    isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime -1 $image /bin/sh 2>&1 | grep "failed to write -1" | grep "cpu.rt_runtime_us: Invalid argument"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-runtime" && ((ret++))

    isula run -itd --cpu-rt-period xx --cpu-rt-runtime 10000 $image /bin/sh 2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-period: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-period" && ((ret++))

    isula run -itd --cpu-rt-period 1000000 --cpu-rt-runtime xx $image /bin/sh 2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-runtime: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-runtime" && ((ret++))

    isula run -itd --cpu-rt-period xx --cpu-rt-runtime xx $image /bin/sh 2>&1 | grep 'Invalid value "xx" for flag --cpu-rt-period: Invalid argument'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid argument for cpu-rt-period" && ((ret++))

    isula run -itd --cpu-rt-period -1 --cpu-rt-runtime 10000 $image /bin/sh 2>&1 | grep "Invalid --cpu-rt-runtime: rt runtime cannot be higher than rt period"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cpu-rt-runtime cannot be higher than cpu-rt-period" && ((ret++))

    isula run -itd --cpu-rt-period 100 --cpu-rt-runtime 10000 $image /bin/sh 2>&1 | grep "Invalid --cpu-rt-runtime: rt runtime cannot be higher than rt period"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cpu-rt-runtime cannot be higher than cpu-rt-period" && ((ret++))
}

declare -i ans=0

if [ -f "/sys/fs/cgroup/cpu/cpu.rt_runtime_us" ];then
    test_cpu_rt_isulad_spec || ((ans++))
    test_cpu_rt_isula_spec || ((ans++))
else
    test_kernel_without_cpu_rt_spec || ((ans++))
fi

show_result ${ans} "${curr_path}/${0}"
