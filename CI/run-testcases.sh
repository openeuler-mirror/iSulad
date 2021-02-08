#!/bin/sh

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
##- @Description: generate cetification
##- @Author: lifeng
##- @Create: 2020-03-30
#######################################################################

set -e
set -x

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH="/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH"
export valgrind_log="/tmp/valgrind.log"

mkdir -p /tmp/coredump
ulimit  -c unlimited
umask 0022
echo "/tmp/coredump/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
ldconfig

function echo_success()
{
    echo -e "\033[1;32m"$@"\033[0m"
}

function echo_error()
{
    echo -e "\033[1;31m"$@"\033[0m"
}

function wait_isulad_running() {
    set +x
    echo "-------waiting isulad running--------"
    waitcnt=0
    while [ 0 ]
    do
        isula version
        if [ $? -eq 0 ];then
            break
        fi
        tail -n 50 /var/lib/isulad/isulad.log
        waitcnt=$(($waitcnt+1))
        maxcnt=60
        if [ $waitcnt -gt $maxcnt ];then
            echo "lcrd is not running more than ${maxcnt}s"
            exit 1
        fi
        sleep 1
    done
    echo "--------isulad is running-----------"
    set -x
}

function start_isulad_with_valgrind() {
    valgrind --fair-sched=yes --log-file=$valgrind_log --tool=memcheck --leak-check=yes -v --track-origins=yes isulad -l DEBUG >/dev/null 2>&1 &
    wait_isulad_running
}

function check_isulad_stopped() {
    maxtimes=15
    curcnt=0

    spid=$1
    while [ $curcnt -lt $maxtimes ]
    do
        ps aux | grep isulad | grep $spid
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
        echo "Stop lcrd with valgrind failed"
        kill -9 $pid
        sleep 1
    fi

    cat $valgrind_log | grep "are definitely lost" | grep "==$pid=="
    if [ $? -eq 0 ];then
        echo "Memory leak may checked by valgrind, see valgrind log file: $valgrind_log"
        sed -n '/definitely lost/,$p' $valgrind_log
        exit 1
    fi
    return 0
}

SRCDIR=`env | grep TOPDIR | awk -F = '{print $2}'`
cd $SRCDIR

set +e
set -x
runflag=$(env | grep TESTCASE_RUNFLAG | awk -F '=' '{print $NF}')
# run integration tests
start_isulad_with_valgrind
if [[ $? -ne 0 ]]; then
    exit 1
fi
env | grep IGNORE_CI
if [ $? -eq 0 ];then
    echo "SKIP TEST"
    check_valgrind_log
    exit 0
fi
echo_success "===================RUN INTEGRATION START========================="
cd ./CI/test_cases
./ci_isula.sh -p isulad -l /
if [[ $? -ne 0 ]]; then
    exit 1
fi
check_valgrind_log
if [[ $? -ne 0 ]]; then
    exit 1
fi
echo_success "====================RUN INTEGRATION END=========================="
