#!/bin/bash
#
# attributes: isulad inheritance ps list
# concurrent: NO
# spend time: 11

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

function do_test_t()
{
    containername=test_list
    containername2=test_list2
    containername3=test_list3
    isula create -t --name $containername busybox
    fn_check_eq "$?" "0" "create failed"
    testcontainer $containername inited

    isula create -t --name $containername2 busybox
    fn_check_eq "$?" "0" "create failed"
    testcontainer $containername2 inited

    isula create -t --name $containername3 busybox
    fn_check_eq "$?" "0" "create failed"
    testcontainer $containername3 inited

    # start container $containername2
    isula start $containername2
    fn_check_eq "$?" "0" "start failed"
    testcontainer $containername2 running

    # ps containers
    cut_output_lines isula ps -a

    if [[ "${lines[1]}" != *"Up"*"$containername2"* ]];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[2]}" != *"Created"* ]];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[3]}" != *"Created"* ]];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    # ps latest container
    cut_output_lines isula ps -l

    if [[ "${lines[1]}" != *"$containername3"* ]];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    # ps last n containers
    cut_output_lines isula ps -n 3

    if [[ "${lines[1]}" != *"$containername3"* ]];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[2]}" != *"$containername2"* ]];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[3]}" != *"$containername"* ]];then
        echo "test failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula stop $containername2
    fn_check_eq "$?" "0" "stop failed"

    isula rm $containername $containername2 $containername3
    fn_check_eq "$?" "0" "rm failed"

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic ps"
