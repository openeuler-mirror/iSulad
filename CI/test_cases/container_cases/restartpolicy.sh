#!/bin/bash
#
# attributes: isulad inheritance restartpolicy
# concurrent: NO
# spend time: 28

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

# $1 : retry limit
# $2 : retry_interval
# $3 : container name
# $4 : expect restart count
function do_retry()
{
    for i in $(seq 1 "$1"); do
        count=`isula inspect --format='{{json .RestartCount}}' ${3}`
        if [ $count -eq $4 ]; then
            return 0
        fi
        sleep $2
    done
    echo "expect $4, get $count"
    return 1
}

function do_test_on_failure()
{
    local retry_limit=15
    local retry_interval=1
    containername=test_rp_on_failure
    isula run  --name $containername  -td --restart on-failure:3  busybox /bin/sh -c "exit 2"
    fn_check_eq "$?" "0" "run failed"

    do_retry ${retry_limit} ${retry_interval} ${containername} 3
    if [[ $? -ne 0 ]];then
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula stop -t 0 $containername
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"
}

function do_test_unless_stopped()
{
    local retry_limit=15
    local retry_interval=1
    containername=test_rp_unless_stopped
    isula run  --name $containername  -td --restart unless-stopped  busybox /bin/sh -c "exit 2"
    fn_check_eq "$?" "0" "run failed"

    do_retry ${retry_limit} ${retry_interval} ${containername} 0
    if [[ $? -ne 0 ]];then
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula stop -t 0 $containername
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"
}

function do_test_unless_stopped_kill()
{
    containername=test_rp_unless_stopped
    isula run  --name $containername  -td --restart unless-stopped  busybox /bin/sh
    fn_check_eq "$?" "0" "run failed"

    cpid=`isula inspect -f '{{json .State.Pid}}' $containername`
    kill -9 $cpid
    sleep 8
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula restart $containername
    testcontainer $containername running

    isula kill $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"
}

function do_test_always_cancel()
{
    containername=test_rp_always_cancel
    isula run  --name $containername  -td --restart always busybox
    testcontainer $containername running

    cpid=`isula inspect -f '{{json .State.Pid}}' $containername`
    kill -9 $cpid
    sleep 8
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"
}

function do_test_t()
{
    do_test_on_failure
    do_test_always_cancel
    do_test_unless_stopped
    do_test_unless_stopped_kill

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic restartpolicy"
