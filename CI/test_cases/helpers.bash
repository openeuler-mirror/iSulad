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
LCR_ROOT_PATH="/var/lib/isulad/engines/lcr"
valgrind_log="/tmp/valgrind.log"
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

function crictl() {
    CRICTL=$(which crictl)
    "$CRICTL" -i unix:///var/run/isulad.sock -r unix:///var/run/isulad.sock "$@"
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

function wait_isulad_running() {
    echo "-------waiting iSulad running--------"
    waitcnt=0
    maxcnt=60
    while [ 0 ]
    do
        isula version
        if [ $? -eq 0 ];then
            break
        fi
        if [ $waitcnt -gt $maxcnt ];then
            echo "iSulad is not running after ${maxcnt}s"
            return 1
        fi
        waitcnt=$(($waitcnt+1))
        sleep 1
    done
    echo "--------iSulad is running-----------"
}

function start_isulad_with_valgrind() {
    valgrind --fair-sched=yes --log-file=$valgrind_log --tool=memcheck --leak-check=yes -v --track-origins=yes isulad $@ -l DEBUG >/dev/null 2>&1 &
    wait_isulad_running
}

function check_isulad_stopped() {
    maxtimes=15
    curcnt=0

    spid=$1
    while [ $curcnt -lt $maxtimes ]
    do
        ps aux | grep isulad | grep -v "grep" | grep -w $spid
        if [ $? -ne 0 ];then
            return 0
        fi
        let "curcnt=$curcnt + 1"
        sleep 1
    done
    return 1
}

function check_valgrind_log() {
    pid=`cat /var/run/isulad.pid`
    kill -15 $pid
    check_isulad_stopped $pid
    if [ $? -ne 0 ];then
        echo "Stop iSulad with valgrind failed"
        kill -9 $pid
        sleep 1
    fi

    cat $valgrind_log | grep "are definitely lost" | grep "==$pid=="
    if [ $? -eq 0 ];then
        echo "Memory leak may checked by valgrind, see valgrind log file: $valgrind_log"
        sed -n '/definitely lost/,// p' $valgrind_log
        exit 1
    fi
    return 0
}

function init_cni_conf()
{
    dtpath="$1"
    mkdir -p /etc/cni/net.d/
    rm -rf /etc/cni/net.d/*
    mkdir -p /opt/cni/bin
    cp $dtpath/bins/isulad-cni /opt/cni/bin
    cp $dtpath/good.conflist /etc/cni/net.d/

    check_valgrind_log
    if [ $? -ne 0 ]; then
        echo "stop isulad failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    start_isulad_with_valgrind --network-plugin cni
    if [ $? -ne 0 ]; then
        echo "start failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    return $TC_RET_T
}
