#!/bin/bash
#
# attributes: isulad root and run dir realpath test
# concurrent: NA
# spend time: 5

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
##- @Create: 2020-09-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_run_root_dir_realpath() {
    local ret=0
    local image="busybox"
    local test="isulad root and run dir realpath test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    reinstall_thinpool
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to reconfig isulad-thinpool" && ((ret++))

    mkdir -p /var/lib/isulad/opt/test_root
    mkdir -p /opt/test_run

    cp -f /etc/isulad/daemon.json /etc/isulad/daemon.bak

    sed -i 's#"graph": "/var/lib/isulad",#"graph": "/var/lib/isulad_test",#g' /etc/isulad/daemon.json
    sed -i 's#"state": "/var/run/isulad",#"state": "/var/run/isulad_test",#g' /etc/isulad/daemon.json

    ln -s /var/lib/isulad/opt/test_root /var/lib/isulad_test
    ln -s /opt/test_run /var/run/isulad_test

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && ((ret++))

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    c_id=$(isula run -itd --cpus 1.5 busybox sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "150000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula restart -t 0 "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "150000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula update --cpus 1.3 --cpu-period 20000 "$c_id" 2>&1 | grep "Nano CPUs and CPU Period cannot both be set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Nano CPUs and CPU Period cannot both be set" && ((ret++))

    isula update --cpus 1.3 --cpu-quota 20000 "$c_id" 2>&1 | grep "Nano CPUs and CPU Quota cannot both be set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Nano CPUs and CPU Quota cannot both be set" && ((ret++))

    isula update --cpu-period 20000 "$c_id" 2>&1 | grep "CPU Period cannot be updated as NanoCPUs has already been set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - CPU Period cannot be updated as NanoCPUs has already been set" && ((ret++))

    isula update --cpu-quota 20000 "$c_id" 2>&1 | grep "CPU Quota cannot be updated as NanoCPUs has already been set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - CPU Quota cannot be updated as NanoCPUs has already been set" && ((ret++))

    isula update --cpus 1.3 "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to update cpus" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "130000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula restart -t 0 "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "130000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula rm -f "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json

    rm -rf /var/lib/isulad/opt/test_root
    rm -rf /opt/test_run
    rm -rf /var/lib/isulad_test
    rm -rf /var/run/isulad_test

    reinstall_thinpool
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to reconfig isulad-thinpool" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

function test_run_root_dir_bind_realpath() {
    local ret=0
    local image="busybox"
    local test="isulad root and run dir realpath test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    reinstall_thinpool
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to reconfig isulad-thinpool" && ((ret++))

    mkdir -p /var/lib/isulad/opt/bind_root
    mkdir -p /opt/bind_run

    cp -f /etc/isulad/daemon.json /etc/isulad/daemon.bak

    sed -i 's#"graph": "/var/lib/isulad",#"graph": "/var/lib/isulad/bind/isulad_test",#g' /etc/isulad/daemon.json
    sed -i 's#"state": "/var/run/isulad",#"state": "/var/run/isulad_test",#g' /etc/isulad/daemon.json

    mkdir -p /var/lib/isulad/bind/isulad_test
    mount --bind /var/lib/isulad/opt/bind_root /var/lib/isulad/bind/isulad_test

    mkdir -p /var/run/isulad_test
    mount --bind /opt/bind_run /var/run/isulad_test

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && ((ret++))

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    c_id=$(isula run -itd --cpus 1.5 busybox sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "150000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula restart -t 0 "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "150000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula update --cpus 1.3 --cpu-period 20000 "$c_id" 2>&1 | grep "Nano CPUs and CPU Period cannot both be set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Nano CPUs and CPU Period cannot both be set" && ((ret++))

    isula update --cpus 1.3 --cpu-quota 20000 "$c_id" 2>&1 | grep "Nano CPUs and CPU Quota cannot both be set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Nano CPUs and CPU Quota cannot both be set" && ((ret++))

    isula update --cpu-period 20000 "$c_id" 2>&1 | grep "CPU Period cannot be updated as NanoCPUs has already been set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - CPU Period cannot be updated as NanoCPUs has already been set" && ((ret++))

    isula update --cpu-quota 20000 "$c_id" 2>&1 | grep "CPU Quota cannot be updated as NanoCPUs has already been set"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - CPU Quota cannot be updated as NanoCPUs has already been set" && ((ret++))

    isula update --cpus 1.3 "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to update cpus" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "130000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula restart -t 0 "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us" | grep "130000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_quota_us: ${image}" && ((ret++))

    isula exec -it "$c_id" sh -c "cat /sys/fs/cgroup/cpu/cpu.cfs_period_us" | grep "100000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check cfs_period_us: ${image}" && ((ret++))

    isula rm -f "$c_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json

    umount /var/lib/isulad/bind/isulad_test
    umount /var/run/isulad_test

    rm -rf /var/lib/isulad/opt/bind_root
    rm -rf /opt/bind_run
    rm -rf /var/lib/isulad/bind/isulad_test
    rm -rf /var/run/isulad_test

    reinstall_thinpool
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to reconfig isulad-thinpool" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

declare -i ans=0

test_run_root_dir_realpath || ((ans++))
test_run_root_dir_bind_realpath || ((ans++))

show_result "${ans}" "${curr_path}/${0}"
