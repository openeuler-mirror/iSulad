#!/bin/bash
#
# attributes: isulad inheritance version
# concurrent: YES
# spend time: 1

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
##- @Author: wangfengtu
##- @Create: 2020-05-12
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ./helpers.bash

function isula_pull()
{
    isula pull busybox
    fn_check_eq "$?" "0" "isula pull busybox"

    isula inspect busybox
    fn_check_eq "$?" "0" "isula inspect busybox"
}

function do_test_t()
{
    isula_pull

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    cat $ISUALD_LOG
    let "ret=$ret + 1"
fi

show_result $ret "basic pull"
