#!/bin/bash
#
# attributes: isulad share namepaces
# concurrent: NO
# spend time: 29

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
##- @Author: gaohuatao
##- @Create: 2020-04-24
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath "$curr_path"/../data)
source ../helpers.sh
arr_ns_type[0]="--ipc"
arr_ns_type[1]="--pid"
arr_ns_type[2]="--net"
arr_ns_type[3]="--uts"

function do_test_t() {
    for ((i = 0; i < ${#arr_ns_type[*]}; i++)); do
        echo ${arr_ns_type[$i]}
        cid[$i]=$(isula create -ti busybox /bin/sh)
        fn_check_eq "$?" "0" "create ${cid[$i]}"

        msg=$(isula run --name test1 -tid ${arr_ns_type[$i]}="container:${cid[$i]}" busybox /bin/sh 2>&1)
        echo "$msg" | grep "Can not join namespace of a non running container"
        fn_check_eq "$?" "0" "share ipc fail test"

        isula rm -f test1

        isula rm -f "${cid[$i]}"

        id=$(isula run -tid busybox /bin/sh)
        fn_check_eq "$?" "0" "run $id"

        test_id=$(isula run -tid ${arr_ns_type[$i]}="container:$id" busybox /bin/sh)
        fn_check_eq "$?" "0" "share ${arr_ns_type[$i]} success test"

        isula restart --time=0 "$id"
        fn_check_eq "$?" "0" "restart container $id"
        testcontainer "$id" running

        isula restart --time=0 "${test_id}"
        fn_check_eq "$?" "0" "restart container ${test_id}"
        testcontainer "${test_id}" running

        isula rm -f "${test_id}" "$id"

    done

    return "$TC_RET_T"
}

ret=0

do_test_t
if [ $? -ne 0 ]; then
    let "ret=$ret + 1"
fi

show_result "$ret" "basic share ns test"
