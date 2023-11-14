#!/bin/bash
#
# attributes: isula attach test
# concurrent: NA
# spend time: 5

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
##- @Author: zhongtao
##- @Create: 2023-11-06
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

# $1 : retry limit
# $2 : retry_interval
# $3 : retry function
function do_retry()
{
    for i in $(seq 1 "$1"); do
        $3 $4 $5
        if [ $? -ne 0 ]; then
            return 0
        fi
        sleep $2
    done
    return 1
}

function get_ioCopy()
{
    ps -T -p $(cat /var/run/isulad.pid) | grep IoCopy
    return $?
}

function inspect_container_status()
{
    [[ $(isula inspect -f '{{.State.Status}}' ${1}) != "${2}" ]]
    return $?
}

function set_up()
{
    local ret=0
    local runtime=$1

    isula run -tid --name test --runtime $runtime busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))
    
    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_attach_fun()
{
    local ret=0
    local retry_limit=20
    local retry_interval=1
    container_name="test"
    local test="test_attach_fun => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    expect <<-END
spawn isula attach test
send \n
expect "*"
sleep 1
send "ls \r"
expect "*"
send "exit \r"
expect "*"
sleep 2
expect eof
END
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to attach container test" && ((ret++))

    count=$(isula logs test | grep ls | wc -l)
    [[ $count -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do attach" && ((ret++))

    do_retry ${retry_limit} ${retry_interval} inspect_container_status  ${container_name} exited
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  incorrent container status: not Exited" && ((ret++))

    (isula attach test > /tmp/test_attach1.log 2>&1) &
    sleep 2
    cat /tmp/test_attach1.log | grep "You cannot attach to a stopped container, start it first"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do attach, except fail" && ((ret++))

    rm -rf /tmp/test_attach1.log

    do_retry ${retry_limit} ${retry_interval} get_ioCopy
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - residual IO copy thread in CRI exec operation" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function tear_down()
{
    local ret=0

    isula rm -f test
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container: test" && ((ret++))

    return ${ret}
}

function do_test_t()
{
    local ret=0
    local runtime=$1
    local test="basic attach test => (${runtime})"
    msg_info "${test} starting..."

    set_up $runtime || ((ret++))

    test_attach_fun  || ((ret++))

    tear_down || ((ret++))

    msg_info "${test} finished with return ${ret}..."

    return $ret
}

ret=0

isula pull busybox
[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

isula images | grep busybox
[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

for element in ${RUNTIME_LIST[@]};
do
    do_test_t $element
    if [ $? -ne 0 ];then
        let "ret=$ret + 1"
    fi
done

show_result $ret "basic attach"

