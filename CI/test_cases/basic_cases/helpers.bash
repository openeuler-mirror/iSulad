#!/bin/bash

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

# testcase result
TC_RET_T=0
declare -a lines

# Root directory of integration tests.
INTEGRATION_ROOT=$(dirname "$(readlink -f "$BASH_SOURCE")")
LCR_ROOT_PATH="/var/lib/isulad/engines/lcr"
ISUALD_LOG="/var/lib/isulad/isulad.log"

declare -r -i FAILURE=-1

function cut_output_lines() {
    message=`$@ 2>&1`
    retval=$?
    oldifs=${IFS}
    IFS=$'\n'
    lines=(${message})
    IFS="${oldifs}"
    return $retval
}

function fn_check_eq() {
    if [[ "$1" -ne "$2" ]];then
        echo "$3"
        TC_RET_T=$(($TC_RET_T+1))
    fi
}

function fn_check_ne() {
    if [[ "$1" -eq "$2" ]];then
        echo "$3"
        TC_RET_T=$(($TC_RET_T+1))
    fi
}

function testcontainer() {
    st=`isula inspect -f '{{json .State.Status}}' "$1"`
    if ! [[ "${st}" =~ "$2" ]];then
        echo "expect status $2, but get ${st}"
        TC_RET_T=$(($TC_RET_T+1))
    fi
}

function msg_ok()
{
    echo -e "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: \033[1;32m$@\033[0m"
}

function msg_err()
{
    echo -e "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: \033[1;31m$@\033[0m" >&2
}

function msg_info()
{
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $@"
}

function show_result() {
    [[ ${1} -ne 0 ]] && msg_err "TESTSUIT: $2 FAILED" && return ${FAILURE}
    msg_ok "TESTSUIT: $2 SUCCESS"
}
