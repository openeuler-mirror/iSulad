#!/bin/bash
#
# attributes: isulad-shim process test
# concurrent: NA
# spend time: 2

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: zhongjiawei
##- @Create: 2026-01-20
#######################################################################

source ../helpers.sh


function do_test_t()
{
    local ret=0
    local test="shim process test"
    msg_info "${test} starting..."

    isulad-shim > /tmp/shim_log 2>&1
    cat /tmp/shim_log |grep "empty SHIIM_LOG_PATH_ENV"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check shim process log path" && ((ret++))
    export ISULAD_SHIIM_LOG_PATH="/tmp/not_exist.fifo"
    isulad-shim > /tmp/shim_log 2>&1
    cat /tmp/shim_log |grep "empty SHIIM_LOG_LEVEL_ENV"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check shim process log level" && ((ret++))
    export ISULAD_SHIIM_LOG_LEVEL="ERROR"
    isulad-shim
    [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check shim process invalid log path, except fail" && ((ret++))
    
    mkfifo /tmp/exist.fifo
    export ISULAD_SHIIM_LOG_PATH="fifo:/tmp/exist.fifo"
    isulad-shim 111 /tmp/not_exist_path 
    [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check shim process invalid args, except fail" && ((ret++))
    
    return $ret
}

function do_post(){
    rm -rf /tmp/exist.fifo
    rm -rf /tmp/shim_log
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi
do_post

show_result $ret "shim process test"

