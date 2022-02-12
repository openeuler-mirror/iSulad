#!/bin/bash
#
# attributes: isulad inheritance fd
# concurrent: NO
# spend time: 16
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

connect="grpc"

function do_test_t_grpc()
{
    if [ $connect != "grpc" ];then
        echo "this test is designed for grpc version"
        return 0
    fi
    sleep 1
    containername=test_fds
    isulad_pid=`cat /var/run/isulad.pid`
    precount=`ls /proc/$isulad_pid/fd | wc -l`
    isula create -t --name $containername busybox
    fn_check_eq "$?" "0" "create failed"
    testcontainer $containername inited

    sleep 1
    curcount=`ls /proc/$isulad_pid/fd | wc -l`
    fn_check_eq "$precount" "$curcount" "test failed"

    isula start $containername
    fn_check_eq "$?" "0" "start failed"
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    sleep 1
    curcount=`ls /proc/$isulad_pid/fd | wc -l`
    fn_check_eq "$precount" "$curcount" "test failed"

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    sleep 1
    curcount=`ls /proc/$isulad_pid/fd | wc -l`
    fn_check_eq "$precount" "$curcount" "test failed"

    return $TC_RET_T
}

function do_test_t_rest()
{
    if [ $connect != "rest" ];then
        echo "this test is designed for rest version"
        return 0
    fi
    sleep 1
    delta_rest="5"
    containername=test_fds
    isulad_pid=`cat /var/run/isulad.pid`
    precount=`ls /proc/$isulad_pid/fd | wc -l`

    isula create -t --name $containername busybox
    fn_check_eq "$?" "0" "create failed"
    testcontainer $containername inited

    sleep 1
    curcount=`ls /proc/$isulad_pid/fd | wc -l`
    delta=$((10#$curcount - 10#$precount))
    echo "delta fd is $delta"
    if [ $delta -ne 0 ] && [ $delta -ne $delta_rest ];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula start $containername
    fn_check_eq "$?" "0" "start failed"
    testcontainer $containername running

    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    sleep 1
    curcount=`ls /proc/$isulad_pid/fd | wc -l`
    delta=$((10#$curcount - 10#$precount))
    echo "delta fd is $delta"
    if [ $delta -ne 0 ] && [ $delta -ne $delta_rest ];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    sleep 1
    curcount=`ls /proc/$isulad_pid/fd | wc -l`
    delta=$((10#$curcount - 10#$precount))
    echo "delta fd is $delta"
    if [ $delta -ne 0 ] && [ $delta -ne $delta_rest ];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    return $TC_RET_T
}

ret=0

do_test_t_grpc
do_test_t_rest
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic check fd leak"
