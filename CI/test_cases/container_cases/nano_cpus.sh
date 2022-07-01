#!/bin/bash
#
# attributes: isulad basic nano iops
# concurrent: NA
# spend time: 5

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
##- @Create: 2020-09-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_cpu_nano_spec()
{
    local ret=0
    local image="busybox"
    local test="container blkio nano test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -itd --cpus 1.5 --cpu-period 20000 $image /bin/sh 2>&1 | grep "Nano CPUs and CPU Period cannot both be set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Nano CPUs and CPU Period cannot both be set" && ((ret++))

    isula run -itd --cpus 1.5 --cpu-quota 20000 $image /bin/sh 2>&1 | grep "Nano CPUs and CPU Quota cannot both be set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Nano CPUs and CPU Quota cannot both be set" && ((ret++))

    c_id=`isula run -itd --cpus 1.5 busybox sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "150000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula restart -t 0 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "150000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula update --cpus 1.3 --cpu-period 20000 $c_id  2>&1 | grep "Nano CPUs and CPU Period cannot both be set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Nano CPUs and CPU Period cannot both be set" && ((ret++))

    isula update --cpus 1.3 --cpu-quota 20000 $c_id  2>&1 | grep "Nano CPUs and CPU Quota cannot both be set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Nano CPUs and CPU Quota cannot both be set" && ((ret++))

    isula update --cpu-period 20000 $c_id  2>&1 | grep "CPU Period cannot be updated as NanoCPUs has already been set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - CPU Period cannot be updated as NanoCPUs has already been set" && ((ret++))

    isula update --cpu-quota 20000 $c_id 2>&1 | grep "CPU Quota cannot be updated as NanoCPUs has already been set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - CPU Quota cannot be updated as NanoCPUs has already been set" && ((ret++))

    isula update --cpus 1.3 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to update cpus" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "130000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula restart -t 0 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "130000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    c_id=`isula run -itd --cpu-period 20000 --cpu-quota 10000 busybox sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula update --cpus 1.4 $c_id 2>&1 | grep "Nano CPUs cannot be updated as CPU Period has already been set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Nano CPUs cannot be updated as CPU Period has already been set" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_cpu_nano_spec || ((ans++))

show_result ${ans} "${curr_path}/${0}"
