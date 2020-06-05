#!/bin/bash
#
# attributes: isulad inheritance create
# concurrent: YES
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
##- @Create: 2020-03-30
#######################################################################

source ../helpers.bash

function do_test_t()
{
    containername=test_create
    isula run -itd --name $containername busybox
    fn_check_eq "$?" "0" "create failed"
    testcontainer $containername running

    isula rm -f $containername
    fn_check_eq "$?" "0" "rm failed"

    isula inspect $containername
    fn_check_ne "$?" "0" "inspect should fail"

    containerid=`isula run -itd --name $containername  --cpu-shares 1024 busybox`
    fn_check_eq "$?" "0" "create failed"

    cat "$LCR_ROOT_PATH/$containerid/config"  | grep "cpu.shares = 1024"
    fn_check_eq "$?" "0" "create failed"

    isula rm -f $containername
    fn_check_eq "$?" "0" "rm failed"

    containerid=`isula run -itd --name $containername  --cpu-quota 50000 busybox`
    fn_check_eq "$?" "0" "create failed"

    cat "$LCR_ROOT_PATH/$containerid/config"  | grep "cpu.cfs_quota_us = 50000"
    fn_check_eq "$?" "0" "create failed"

    isula rm -f $containername
    fn_check_eq "$?" "0" "rm failed"

    containerid=`isula run -itd --name $containername  --cpuset-cpus 0-1 busybox`
    fn_check_eq "$?" "0" "create failed"

    cat "$LCR_ROOT_PATH/$containerid/config"  | grep "cpuset.cpus = 0-1"
    fn_check_eq "$?" "0" "create failed"

    isula rm -f $containername
    fn_check_eq "$?" "0" "rm failed"

    containerid=`isula run -itd --name $containername  --memory 1000000000 busybox`
    fn_check_eq "$?" "0" "create failed"

    cat "$LCR_ROOT_PATH/$containerid/config"  | grep "memory.limit_in_bytes = 1000000000"
    fn_check_eq "$?" "0" "create failed"

    isula rm -f $containername
    fn_check_eq "$?" "0" "rm failed"

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic create"
