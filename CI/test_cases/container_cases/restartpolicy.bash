#!/bin/bash
#
# attributes: isulad inheritance restartpolicy
# concurrent: NO
# spend time: 29

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
##- @Create: 2020-03-30
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.bash

function do_test_on_failure()
{
    containername=test_rp_on_failure
    isula run  --name $containername  -td --restart on-failure:3  busybox /bin/sh -c "exit 2"
    fn_check_eq "$?" "0" "run failed"

    sleep 8
    count=`isula inspect --format='{{json .RestartCount}}' $containername`
    if [[ $count != "3"  ]];then
        echo "expect 3 but get $count"
        TC_RET_T=$(($TC_RET_T+1))
    fi
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

    isula stop $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"
}

function do_test_t()
{
    do_test_on_failure
    do_test_always_cancel

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic restartpolicy"
