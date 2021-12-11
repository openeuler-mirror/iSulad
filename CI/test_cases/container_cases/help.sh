#!/bin/bash
#
# attributes: isulad inheritance help
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
##- @Author: lifeng
##- @Create: 2020-03-30
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath "$curr_path"/../data)
source ../helpers.sh

function isulad_help() {
    isulad --help
    fn_check_eq "$?" "0" "test failed"
}

function isula_help() {
    isula
    fn_check_eq "$?" "0" "test failed"

    isula --help
    fn_check_eq "$?" "0" "test failed"
}

function isula_subcmd_help() {
    isula create --help
    fn_check_eq "$?" "0" "test failed"

    isula rm --help
    fn_check_eq "$?" "0" "test failed"

    isula ps --help
    fn_check_eq "$?" "0" "test failed"

    isula start --help
    fn_check_eq "$?" "0" "test failed"

    isula stop --help
    fn_check_eq "$?" "0" "test failed"

    isula exec --help
    fn_check_eq "$?" "0" "test failed"

    isula version --help
    fn_check_eq "$?" "0" "test failed"

    isula foo --help
    fn_check_ne "$?" "0" "test failed"
}

function do_test_t() {
    isulad_help
    isula_help
    isula_subcmd_help

    return "$TC_RET_T"
}

ret=0

do_test_t
if [ $? -ne 0 ]; then
    let "ret=$ret + 1"
fi

show_result "$ret" "basic help"
