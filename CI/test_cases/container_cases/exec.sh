#!/bin/bash
#
# attributes: isulad exec
# concurrent: YES
# spend time: 1

#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2021. All rights reserved.
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
##- @Create: 2021-03-09
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath "$curr_path"/../data)
source ../helpers.sh
test="exec test => test_exec"

function exec_workdir() {
    local ret=0

    isula rm -f $(isula ps -a -q)

    isula run -tid -n cont_workdir busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with --workdir" && ((ret++))

    isula exec -ti --workdir /workdir cont_workdir pwd | grep "/workdir"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - workdir is not /workdir failed" && ((ret++))

    isula rm -f $(isula ps -a -q)

    return "${ret}"
}

declare -i ans=0

msg_info "${test} starting..."

exec_workdir || ((ans++))

msg_info "${test} finished with return ${ret}..."

show_result "${ans}" "${curr_path}/${0}"
