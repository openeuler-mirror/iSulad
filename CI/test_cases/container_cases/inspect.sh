#!/bin/bash
#
# attributes: isulad basic container hook
# concurrent: NA
# spend time: 6

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
##- @Create: 2020-06-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
test_data_path=$(realpath $curr_path/test_data)

function test_inspect_spec()
{
    local ret=0
    local image="busybox"
    local test="container inspect test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    containername=test_inspect

    isula create --name $containername --ipc host --pid host --uts host --restart=on-failure:10 --hook-spec ${test_data_path}/test-hookspec.json --cpu-shares 100 --memory 5MB --memory-reservation 4MB --cpu-period 1000000 --cpu-quota 200000  --cpuset-cpus 1 --cpuset-mems 0 --kernel-memory 50M --pids-limit=10000 --volume /home:/root --env a=1 $image /bin/sh ls
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Path}}' $containername 2>&1 | grep "/bin/sh"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Args}}' $containername 2>&1 | grep "ls"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.IpcMode}}' $containername 2>&1 | grep "host"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.PidMode}}' $containername 2>&1 | grep "host"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.UTSMode}}' $containername 2>&1 | grep "host"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.RestartPolicy.Name}}' $containername 2>&1 | grep "on-failure"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.RestartPolicy.MaximumRetryCount}}' $containername 2>&1 | grep "10"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.HookSpec}}' $containername 2>&1 | grep "test-hookspec.json"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.Binds}}' $containername 2>&1 | grep "/home:/root"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.CPUShares}}' $containername 2>&1 | grep "100"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.Memory}}' $containername 2>&1 | grep "5242880"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.MemoryReservation}}' $containername 2>&1 | grep "4194304"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.CPUPeriod}}' $containername 2>&1 | grep "1000000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.CPUQuota}}' $containername 2>&1 | grep "200000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.CpusetCpus}}' $containername 2>&1 | grep "1"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.CpusetMems}}' $containername 2>&1 | grep "0"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.KernelMemory}}' $containername 2>&1 | grep "52428800"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .HostConfig.PidsLimit}}' $containername 2>&1 | grep "10000"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{.Config.Image}}' $containername 2>&1 | grep ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    image_id=$(isula inspect -f '{{.image.id}}' ${image})
    isula inspect --format='{{.Image}}' $containername 2>&1 | grep "sha256:${image_id}"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    if [ -d /sys/fs/cgroup/files ];then
        grepval="100"
	else
        grepval="0"
    fi
    isula inspect --format='{{json .HostConfig.FilesLimit}}' $containername 2>&1 | grep "$grepval"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Config.Env}}' $containername 2>&1 | grep "a=1"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Config.Cmd}}' $containername 2>&1 | grep "ls"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula rm -f $containername
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    containername=test_inspect_entrypoint
    isula create --entrypoint /bin/sh --name $containername $image -c "exit 0"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Path}}' $containername 2>&1 | grep "/bin/sh"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Args}}' $containername 2>&1 | grep "exit 0"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Config.Entrypoint}}' $containername 2>&1 | grep "/bin/sh"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect --format='{{json .Config.Cmd}}' $containername 2>&1 | grep "exit 0"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect -f "{{json .State.Status}} {{.Name}}" $containername 2>&1 | sed -n '1p' | grep "inited"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula inspect -f "{{json .State.Status}} {{.Name}}" $containername 2>&1 | sed -n '2p' | grep ${containername}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check container with image: ${image}" && ((ret++))

    isula rm -f $containername

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_inspect_spec || ((ans++))

show_result ${ans} "${curr_path}/${0}"
