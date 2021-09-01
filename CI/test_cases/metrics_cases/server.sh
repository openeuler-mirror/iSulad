#!/bin/bash
#
# attributes: isulad metrics port test
# concurrent: NA
# spend time: 1

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

function test_server()
{
    local ret=0
    local test="container stats test => (${FUNCNAME[@]})"
    local req_cnt=0
    local metrics_log=/tmp/metrics.log
    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop isulad" && return ${FAILURE}

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start isulad" && return ${FAILURE}

    # iSulad is started by valgrind, netstat cannot find the 'isulad' process name
    # 127.0.0.0:9090
    local metric_server=$(netstat -antp | grep 9090 | awk '{print $4}')
    [[ -z $metric_server ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to find metrics http server" && ((ret++))

    curl -i $metric_server/metrics/type >> $metrics_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run curl" && ((ret++))

    head -n1 $metrics_log | cut -d ' ' -f2 | grep 200
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - metric server response error" && ((ret++))

    req_cnt=$(cat $metrics_log | grep isula_metrics_http_req_count | tail -n1 | awk '{print $2}')
    [[ $req_cnt -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - metric server response not correctly" && ((ret++))

    rm -rf $metrics_log
    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_server || ((ans++))

show_result ${ans} "${curr_path}/${0}"
