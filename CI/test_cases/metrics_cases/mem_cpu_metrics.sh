#!/bin/bash
#
# attributes: isulad mem metrics test
# concurrent: NA
# spend time: 10

#######################################################################
##- @Copyright (c) KylinSoft  Co., Ltd. 2021. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: xiapin
##- @Create: 2021-08-18
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_mem() {
    local ret=0
    local test="container stats test => (${FUNCNAME[@]})"
    local metrics_log=/tmp/metrics.log
    local image="busybox"
    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop isulad" && return "${FAILURE}"

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start isulad" && return "${FAILURE}"

    # iSulad is started by valgrind, netstat cannot find the 'isulad' process name
    # 127.0.0.0:9090
    metric_server=$(netstat -antp | grep 9090 | awk '{print $4}')
    [[ -z $metric_server ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to find metrics http server" && ((ret++))

    local cont_id=$(isula create -t $image | cut -b 1-4)
    [[ -z $cont_id ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create cont with img $image" && ((ret++))

    isula start "$cont_id"
    fn_check_eq "$?" "0" "start failed"

    #mem info (get base cpu info)
    curl -i "$metric_server"/metrics/type/mem_cpu >> $metrics_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run curl" && ((ret++))

    cat $metrics_log | grep "isula_container_mem_stat" | grep "$cont_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to get mem metrics info" && ((ret++))

    #cpu info
    curl -i "$metric_server"/metrics/type/cpu >> $metrics_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run curl" && ((ret++))

    cat $metrics_log | grep "isula_container_cpu_stat" | grep "$cont_id"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to get cpu metrics info" && ((ret++))

    isula stop "$cont_id"
    isula rm "$cont_id"
    #rm -rf $metrics_log
    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

declare -i ans=0

test_mem || ((ans++))

show_result "${ans}" "${curr_path}/${0}"
