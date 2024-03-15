#!/bin/bash
#
# attributes: isulad systemd cgroup run
# concurrent: NO
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
##- @Author: jikai
##- @Create: 2024-02-05
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh

function test_systemd_cgroup()
{
    local ret=0
    local runtime=$1
    local image="busybox"

    local test="systemd cgroup driver test with (${runtime})=> (${FUNCNAME[@]})"
    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind --systemd-cgroup
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    cid1=$(isula run -tid --runtime $runtime -m 10M $image /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start container failed" && ((ret++))
    cat /sys/fs/cgroup/memory/system.slice/isulad-$cid1.scope/memory.limit_in_bytes | grep ^10485760$
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check memory limit failed" && ((ret++))

    cid2=$(isula run -tid --runtime $runtime --cgroup-parent /test $image /bin/sh)
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start container failed" && ((ret++))

    cid3=$(isula run -tid --runtime $runtime -m 10M --cgroup-parent test-a-b.slice $image /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start container failed" && ((ret++))
    cat /sys/fs/cgroup/memory/test.slice/test-a.slice/test-a-b.slice/isulad-$cid3.scope/memory.limit_in_bytes | grep ^10485760$
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check memory limit failed" && ((ret++))

    isula rm -f $cid1 $cid2 $cid3
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm container failed" && ((ret++))

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    rm -rf $ulimitlog

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

for element in ${RUNTIME_LIST[@]};
do
    # lcr does not support systemd cgroup driver
    if [ "$element" == "lcr" ];then
        continue
    fi
    test_systemd_cgroup $element || ((ans++))
done

show_result ${ans} "${curr_path}/${0}"
