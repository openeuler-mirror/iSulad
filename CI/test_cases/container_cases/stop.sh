#!/bin/bash
#
# attributes: isulad inheritance stop
# concurrent: YES
# spend time: 27

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
    local runtime=$1
    local test="start_test => (${runtime})"
    msg_info "${test} starting..."

    containername=test_stop
    isula run --runtime $runtime --name $containername -td busybox
    fn_check_eq "$?" "0" "run failed"
    testcontainer $containername running

    isula stop $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula start $containername
    fn_check_eq "$?" "0" "start failed"
    testcontainer $containername running

    isula stop --force $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula start $containername
    fn_check_eq "$?" "0" "start failed"
    testcontainer $containername running

    isula stop --time 10 $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula start $containername
    fn_check_eq "$?" "0" "start failed"
    testcontainer $containername running

    isula stop --time 10 --force $containername
    fn_check_eq "$?" "0" "stop failed"
    testcontainer $containername exited

    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    msg_info "${test} finished with return ${ret}..."

    return $TC_RET_T
}

ret=0

for element in ${RUNTIME_LIST[@]};
do
    do_test_t $element
    if [ $? -ne 0 ];then
        let "ret=$ret + 1"
    fi
done

show_result $ret "basic stop"
