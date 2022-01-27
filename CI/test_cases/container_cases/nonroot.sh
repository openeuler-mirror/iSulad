#!/bin/bash
#
# attributes: isulad inheritance start
# concurrent: YES
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
##- @Author: gaohuatao
##- @Create: 2020-10-19
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh
group="isula"
user="nonroot_test"
container="test_nonroot_user"

function do_test_t()
{
    local ret=0
    local test="isula execute with non root => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    userdel $user
    useradd -g $group $user
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - add user $user and add to group $group failed" && ((ret++))

    su - $user -c "isula run -tid --name $container busybox /bin/bash"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container failed" && ((ret++))

    su - $user -c "isula inspect $container"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect container failed" && ((ret++))

    su - $user -c "isula restart $container"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - restart container failed" && ((ret++))

    su - $user -c "isula exec $container pwd"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec container failed" && ((ret++))

    su - $user -c "isula stop $container"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop container failed" && ((ret++))

    su - $user -c "isula rm $container"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm container failed" && ((ret++))

    userdel $user

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic start"
