#!/bin/bash
#
# attributes: isulad inheritance rm
# concurrent: YES
# spend time: 24

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
data_path=$(realpath "$curr_path"/../data)
source ../helpers.sh

function rm_stopped_container() {
    containername=test_rm_stopped
    isula create -t --name $containername busybox
    fn_check_eq "$?" "0" "create failed"
    testcontainer $containername inited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    isula inspect $containername
    fn_check_ne "$?" "0" "inspect should fail"
}

function rm_running_container() {
    containername=test_rm_running
    isula run -td --name $containername busybox
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername running

    isula rm $containername
    fn_check_ne "$?" "0" "rm should fail"

    isula stop $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    isula inspect $containername
    fn_check_ne "$?" "0" "inspect should fail"
}

function rm_running_container_force() {
    containername=test_rm_running_force
    conID=$(isula run -td --name $containername busybox)
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername running

    # lock config file
    chattr +i /var/lib/isulad/engines/lcr/"${conID}"/config

    # Create a deep directory
    isula exec -it "${conID}" /bin/sh -c "dir=/a;i=0;while [ \${i} -le 2048 ]; do mkdir \${dir}; dir=\${dir}/a; let i=\${i}+1; done"
    fn_check_eq "$?" "0" "exec failed"

    isula rm --force $containername
    fn_check_eq "$?" "0" "rm failed"

    isula inspect $containername
    fn_check_ne "$?" "0" "inspect should fail"
}

function do_test_t() {
    rm_stopped_container
    rm_running_container
    rm_running_container_force

    return "$TC_RET_T"
}

ret=0

do_test_t
if [ $? -ne 0 ]; then
    let "ret=$ret + 1"
fi

show_result "$ret" "basic rm"
