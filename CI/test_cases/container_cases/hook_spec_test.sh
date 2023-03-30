#!/bin/bash
#
# attributes: isulad basic container hook
# concurrent: NA
# spend time: 9

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
##- @Create: 2020-06-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

test_data_path=$(realpath $curr_path/test_data)

function test_hook_spec()
{
    local ret=0
    local image="busybox"
    local test="container hook test => (${FUNCNAME[@]})"
    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    cat > /tmp/env.sh <<EOF
#!/bin/bash

env > /tmp/envfile
EOF
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to generate env shell" && ((ret++))

    chmod +x /tmp/env.sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to chmod env shell" && ((ret++))

    CONT=`isula run -itd --hook-spec ${test_data_path}/test-hookspec.json ${image}`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula stop -t 0 ${CONT}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop ${CONT}" && ((ret++))

    isula rm ${CONT}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm ${CONT}" && ((ret++))

    # debug
    cat /tmp/envfile
    cat /tmp/envfile | grep "PATH=/usr/local/bin:/usr/bin"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - set ocihook PATH env failed" && ((ret++))

    cat /tmp/envfile | grep "AAA=bbb"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - set ocihook env failed" && ((ret++))

    rm -rf /tmp/env.sh
    rm -rf /tmp/envfile

    runlog=/tmp/hook_permission.log
    no_permission_container="test_no_permission"
    isula run -n $no_permission_container -itd --hook-spec ${test_data_path}/no_permission.json ${image} > $runlog 2>&1
    [[ $? -ne 126 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check exit code container with image: ${image}" && ((ret++))

    cat $runlog | grep "Permission denied"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to get no_permission output: ${image}" && ((ret++))

    isula rm -f $no_permission_container
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm $no_permission_container" && ((ret++))

    rm -rf $runlog

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_hook_spec || ((ans++))

show_result ${ans} "${curr_path}/${0}"
