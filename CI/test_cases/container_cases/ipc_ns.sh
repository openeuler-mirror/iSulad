#!/bin/bash
#
# attributes: isulad ipc namespace usage
# concurrent: NO
# spend time: 29

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
##- @Author: haozi007
##- @Create: 2023-06-05
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function do_test_t()
{
    cid=$(isula create --name test1 -ti --ipc=shareable busybox /bin/sh)

    cat /proc/1/mountinfo | grep "$cid/mounts/shm"
    fn_check_eq "$?" "0" "shareable ipc lose shm mount point"

    isula rm -f test1
    cat /proc/1/mountinfo | grep "$cid/mounts/shm"
    fn_check_ne "$?" "0" "residual shm mount poit"

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic ipc namespace usage test"
