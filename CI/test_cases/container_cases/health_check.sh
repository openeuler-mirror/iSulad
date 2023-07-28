#!/bin/bash
#
# attributes: isulad basic container create run healthcheck
# concurrent: NA
# spend time: 20

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
##- @Author: WuJing
##- @Create: 2020-07-07
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

image="busybox"
isula pull ${image}
[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" &&  exit ${FAILURE}

# $1 : retry limit
# $2 : retry_interval
# $3 : retry function
# $4 : retry function parms 1
# $5 : retry function parms 2
function do_retry()
{
    for i in $(seq 1 "$1"); do
        $3 $4 $5
        if [ $? -eq 0 ]; then
            return 0
        fi
        sleep $2
    done
    return 1
}

function inspect_container_health_status()
{
    [[ $(isula inspect -f '{{.State.Health.Status}}' ${1}) == "${2}" ]]
    return $?
}

function inspect_container_status()
{
    [[ $(isula inspect -f '{{.State.Status}}' ${1}) == "${2}" ]]
    return $?
}

function inspect_container_exitcode()
{
    [[ $(isula inspect -f '{{.State.ExitCode}}' ${1}) == "${2}" ]]
    return $?
}

function inspect_container_failing_streak()
{
    [[ $(isula inspect -f '{{.State.Health.FailingStreak}}' ${1}) == "${2}" ]]
    return $?
}

function test_health_check_paraments()
{
    local ret=0
    local retry_limit=10
    local retry_interval=1
    local test="list && inspect image info test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula images | grep ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    container_name="health_check_para"
    isula run -itd --runtime $1 -n ${container_name} --health-cmd 'echo "iSulad" ; exit 1' \
        --health-interval 5s --health-retries 2 --health-start-period 8s --health-exit-on-unhealthy ${image} /bin/sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    # start period : 2s => do health check => interval: 2s => do health check => exit on unhealthy
    do_retry ${retry_limit} ${retry_interval} inspect_container_status  ${container_name} running
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container status: not running" && ((ret++))

    # finish first health check
    sleep 10
    do_retry ${retry_limit} ${retry_interval} inspect_container_health_status  ${container_name} starting
    # keep starting status with health check return non-zero at always until status change to unhealthy
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container health check status: not starting" && ((ret++))

    sleep 6 # finish second health check

    success=1
    do_retry ${retry_limit} ${retry_interval} inspect_container_health_status  ${container_name} unhealthy
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container health check status: not unhealthy" && ((ret++))

    # validate --health-retries option
    do_retry ${retry_limit} ${retry_interval} inspect_container_failing_streak  ${container_name} 2
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container health check failing streak: not 2" && ((ret++))

    do_retry ${retry_limit} ${retry_interval} inspect_container_status  ${container_name} exited
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container status: not exited" && ((ret++))

    do_retry ${retry_limit} ${retry_interval} inspect_container_exitcode  ${container_name} 137
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container exit code: not 137" && ((ret++))

    isula rm -f ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container: ${container_name}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_health_check_normally()
{
    local ret=0
    local image="busybox"
    local retry_limit=10
    local retry_interval=1
    local test="list && inspect image info test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula images | grep ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    container_name="health_check_normally"
    isula run -itd --runtime $1 -n ${container_name} --health-cmd 'date' --health-interval 5s ${image} /bin/sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    # start period : 0s => interval: 2s => do health check => interval: 2s => do health check => ...
    do_retry ${retry_limit} ${retry_interval} inspect_container_status  ${container_name} running
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container status: not running" && ((ret++))

    # Health check has been performed yet
    do_retry ${retry_limit} ${retry_interval} inspect_container_health_status  ${container_name} starting
    # Initial status when the container is still starting
    [[ $? -ne 0 ]]  && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container health check status: not starting" && ((ret++))

    sleep 8 # finish first health check
    
    do_retry ${retry_limit} ${retry_interval} inspect_container_health_status  ${container_name} healthy
    # When the health check returns successfully, status immediately becomes healthy
    [[ $? -ne 0 ]]  && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container health check status: not healthy" && ((ret++))

    kill -9 $(isula inspect -f '{{.State.Pid}}' ${container_name})
    
    # Wait for the container to be killed
    do_retry ${retry_limit} ${retry_interval} inspect_container_health_status  ${container_name} unhealthy
    # The container process exits abnormally and the health check status becomes unhealthy
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container health check status: not unhealthy" && ((ret++))

    do_retry ${retry_limit} ${retry_interval} inspect_container_exitcode  ${container_name} 137
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container exit code: not 137" && ((ret++))

    isula rm -f ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container: ${container_name}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_health_check_timeout()
{
    local ret=0
    local image="busybox"
    local retry_limit=10
    local retry_interval=1
    local success=1
    local test="list && inspect image info test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula images | grep ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    container_name="health_check_timeout"
    isula run -itd --runtime $1 -n ${container_name} --health-cmd 'sleep 5' --health-interval 5s --health-timeout 1s \
        --health-retries 1 --health-exit-on-unhealthy ${image} /bin/sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    # start period : 0s => interval: 5s => do health check(1s timeout) => unhealthy(exited)
    do_retry ${retry_limit} ${retry_interval} inspect_container_status  ${container_name} running
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container status: not running" && ((ret++))

    # Health check has been performed yet
    do_retry ${retry_limit} ${retry_interval} inspect_container_health_status  ${container_name} starting
    # Initial status when the container is still starting
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container health check status: not starting" && ((ret++))

    sleep 7 # finish first health check
    
    do_retry ${retry_limit} ${retry_interval} inspect_container_health_status  ${container_name} unhealthy
    # The container process exits and the health check status becomes unhealthy
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container health check status: not unhealthy" && ((ret++))

    do_retry ${retry_limit} ${retry_interval} inspect_container_exitcode  ${container_name} 137
    [[ $? -ne 0 ]]  && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container exit code: not 137" && ((ret++))

    isula rm -f ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container: ${container_name}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_health_check_monitor()
{
    local ret=0
    local image="busybox"
    local test="health check monitor test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula images | grep ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula rm -f $(isula ps -qa)

    container_name="health_check_monitor"
    isula run -itd --runtime $1 -n ${container_name} --health-cmd="sleep 3" --health-interval 3s  busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula stop -t 0 ${container_name} && isula start ${container_name} && \
        isula stop -t 0 ${container_name} && isula start ${container_name}

    health_check_monitor_count=$(ps -T -p $(cat /var/run/isulad.pid) | grep HealthCheck | wc -l)
    [[ ${health_check_monitor_count} -ne 1 ]] && \
        msg_err "${FUNCNAME[0]}:${LINENO} - multiple health check monitor thread container: ${container_name}" && ((ret++))

    isula rm -f ${container_name}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container: ${container_name}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

for element in ${RUNTIME_LIST[@]};
do
    test="health check test => (${element})"
    msg_info "${test} starting..."

    test_health_check_paraments $element || ((ans++))

    test_health_check_normally $element || ((ans++))

    test_health_check_timeout $element || ((ans++))

    test_health_check_monitor $element || ((ans++))

    msg_info "${test} finished with return ${ans}..."
done

show_result ${ans} "${curr_path}/${0}"