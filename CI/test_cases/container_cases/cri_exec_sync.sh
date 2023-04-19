#!/bin/bash
#
# attributes: cri exec sync test
# concurrent: NA
# spend time: 14

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
##- @Author: zhongtao
##- @Create: 2023-04-18
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/criconfigs)
pause_img_path=$(realpath $curr_path/test_data)
source ../helpers.sh

function do_pre()
{
    local ret=0
    local image="busybox"
    local podimage="mirrorgooglecontainers/pause-amd64"
    local test="set_up => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    cp /etc/isulad/daemon.json /etc/isulad/daemon.bak
    sed -i "s#\"pod-sandbox-image\": \"\"#\"pod-sandbox-image\": \"mirrorgooglecontainers/pause-amd64:3.0\"#g" /etc/isulad/daemon.json

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop isulad" && return ${FAILURE}

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start isulad" && return ${FAILURE}

    isula load -i ${pause_img_path}/pause.tar
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to load pause image" && return ${FAILURE}

    crictl pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    crictl images | grep ${podimage}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${podimage}" && ((ret++))

    return ${ret}
}

function set_up()
{
    local ret=0
    sid=$(crictl runp --runtime $1 ${data_path}/sandbox-config.json)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run sandbox" && ((ret++))

    cid=$(crictl create $sid ${data_path}/container-config.json ${data_path}/sandbox-config.json)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container" && ((ret++))

    crictl start $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start container" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_cri_exec_sync_fun()
{
    local ret=0
    local test="test_cri_exec_sync_fun => (${FUNCNAME[@]})"
    msg_info "${test} starting..."
    
    crictl exec -s ${cid} xxx 2>&1
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to catch exec sync error msg" && ((ret++))

    crictl exec -s ${cid} date
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to exec sync" && ((ret++))

    crictl exec -s --timeout 2 ${cid} ls
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to exec sync with timeout" && ((ret++))

    crictl exec -s --timeout 2 ${cid} sleep 898989 2>&1 | grep "timeout"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to catch exec sync timeout error msg" && ((ret++))

    crictl exec -s --timeout 2 ${cid} ps 2>&1 | grep "sleep 898989"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - residual exec process" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function tear_down()
{
    local ret=0

    crictl stop $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop container" && ((ret++))

    crictl rm $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container" && ((ret++))

    crictl stopp $sid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop sandbox" && ((ret++))

    crictl rmp $sid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm sandbox" && ((ret++))

    return ${ret}
}

function do_post()
{
    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    
    check_valgrind_log
    start_isulad_with_valgrind
}

function do_test_t()
{
    local ret=0
    local runtime=$1
    local test="cri_exec_sync_test => (${runtime})"
    msg_info "${test} starting..."

    set_up $runtime || ((ret++))

    test_cri_exec_sync_fun  || ((ret++))

    tear_down || ((ret++))

    msg_info "${test} finished with return ${ret}..."

    return $ret
}

declare -i ans=0

do_pre || ((ans++))

for element in ${RUNTIME_LIST[@]};
do
    do_test_t $element || ((ans++))
done

do_post

show_result ${ans} "${curr_path}/${0}"
