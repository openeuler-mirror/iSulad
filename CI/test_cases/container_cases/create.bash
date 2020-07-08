#!/bin/bash
#
# attributes: isulad inheritance create basic
# concurrent: YES
# spend time: 4

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

    # validate --label
    containerid=`isula run -itd --name $containername  --label "iSulad=lcrd" busybox`
    fn_check_eq "$?" "0" "create failed"

    isula inspect -f "{{.Config.Labels}}" ${containerid} | grep iSulad | grep lcrd
    fn_check_eq "$?" "0" " failed to set meta data on a container"

    isula rm -f $containername
    fn_check_eq "$?" "0" "rm failed"

    # validate --label-file
    echo "iSulad=lcrd\n   abc=kkk" > ./label_file
    containerid=`isula run -itd --name $containername  --label-file ./label_file busybox`
    fn_check_eq "$?" "0" "create failed"

    isula inspect -f "{{.Config.Labels}}" ${containerid} | grep iSulad | grep lcrd
    fn_check_eq "$?" "0" "failed to read in a line delimited file of labels and set meta data on a container"

    isula inspect -f "{{.Config.Labels}}" ${containerid} | grep abc | grep kkk
    fn_check_eq "$?" "0" "failed to read in a line delimited file of labels and set meta data on a container"

    rm -f ./label_file

    isula rm -f $containername
    fn_check_eq "$?" "0" "rm failed"

    # validate --dns --dns-search --dns-opt
    containerid=`isula run -itd --name $containername --dns 8.8.8.8 --dns-opt debug --dns-search example.com busybox`
    fn_check_eq "$?" "0" "create failed"

    isula exec -it ${containerid} cat /etc/resolv.conf | grep "nameserver 8.8.8.8"
    fn_check_eq "$?" "0" "failed to set custom DNS servers"

    isula exec -it ${containerid} cat /etc/resolv.conf | grep "search" | grep "example.com"
    fn_check_eq "$?" "0" "failed to set custom DNS search domains"

    isula exec -it ${containerid} cat /etc/resolv.conf | grep "options" | grep "debug"
    fn_check_eq "$?" "0" "failed to set DNS options"

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
