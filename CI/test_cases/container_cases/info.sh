#!/bin/bash
#
# attributes: isula info operator
# concurrent: YES
# spend time: 1

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
##- @Author: haozi007
##- @Create: 2023-09-04
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh

function do_test_t()
{
    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))
    export http_proxy="http://test:123456@testproxy.com"
    export https_proxy="http://test:123456@testproxy.com"
    export no_proxy="127.0.0.1"
    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))
    isula info | grep "Http Proxy" | grep "http://xxxx:xxxx@testproxy.com"
    fn_check_eq "$?" "0" "check http proxy failed"
    isula info | grep "Https Proxy" | grep "http://xxxx:xxxx@testproxy.com"
    fn_check_eq "$?" "0" "check https proxy failed"
    isula info | grep "No Proxy" | grep "127.0.0.1"
    fn_check_eq "$?" "0" "check no proxy failed"

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))
    export http_proxy="https://example.com"
    export no_proxy="127.0.0.1"
    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))
    isula info | grep "Http Proxy" | grep "https://example.com"
    fn_check_eq "$?" "0" "check http proxy failed"
    isula info | grep "No Proxy" | grep "127.0.0.1"
    fn_check_eq "$?" "0" "check no proxy failed"

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))
    export http_proxy="http//abc.com"
    export no_proxy="127.0.0.1:localhost"
    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))
    isula info | grep "Http Proxy"
    fn_check_ne "$?" "0" "check http proxy failed"
    isula info | grep "No Proxy"
    fn_check_ne "$?" "0" "check no proxy failed"

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))
    export http_proxy="http//xxxx@abc:abc.com"
    export no_proxy="127.0.0.1"
    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))
    isula info | grep "Http Proxy"
    fn_check_ne "$?" "0" "check http proxy failed"
    isula info | grep "No Proxy"
    fn_check_ne "$?" "0" "check no proxy failed"

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))
    unset https_proxy http_proxy no_proxy
    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))
    isula info | grep "Http Proxy"
    fn_check_ne "$?" "0" "check http proxy failed"
    isula info | grep "No Proxy"
    fn_check_ne "$?" "0" "check no proxy failed"

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic info"
