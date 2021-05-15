#!/bin/bash
#
# attributes: isulad inheritance version
# concurrent: YES
# spend time: 10

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
##- @Author: wangfengtu
##- @Create: 2020-05-12
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh

function isula_pull()
{
    isula rm -f `isula ps -a -q`

    isula pull busybox
    fn_check_eq "$?" "0" "isula pull busybox"

    local isulad_pid=$(cat /var/run/isulad.pid)

    # wait some time to make sure fd closed
    sleep 3
    local fd_num1=$(ls -l /proc/$isulad_pid/fd | wc -l)
    [[ $fd_num1 -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - can not get fd number" && ((ret++))
    ls -l /proc/$isulad_pid/fd

    isula rmi busybox

    for i in `seq 1 10`
    do
        isula pull busybox &
    done
    isula pull busybox
    fn_check_eq "$?" "0" "isula pull busybox"
    wait

    # wait some time to make sure fd closed
    sleep 3
    local fd_num2=$(ls -l /proc/$isulad_pid/fd | wc -l)
    [[ $fd_num2 -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - can not get fd number" && ((ret++))
    ls -l /proc/$isulad_pid/fd

    # make sure fd not increase after remove and pull busybox
    [[ $fd_num1 -ne $fd_num2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fd number not right" && ((ret++))

    isula inspect busybox
    fn_check_eq "$?" "0" "isula inspect busybox"

    # test --pull always option
    isula run --rm -ti --pull always busybox echo hello 2>&1 | grep pulling
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --pull always failed" && ((ret++))

    # test --pull never option
    isula rm -f `isula ps -a -q`
    isula rmi busybox
    isula run --rm -ti --pull never busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --pull never failed" && ((ret++))

    # test default --pull option (missing)
    isula run --rm -ti busybox echo hello 2>&1 | grep pulling
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --pull missing failed" && ((ret++))

    isula pull hub.c.163.com/public/centos:6.7-tools
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --pull hub.c.163.com/public/centos:6.7-tools failed" && ((ret++))

    isula pull docker.io/library/busybox:latest
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --pull docker.io/library/busybox:latest failed" && ((ret++))

    isula pull 3laho3y3.mirror.aliyuncs.com/library/busybox
    fn_check_eq "$?" "0" "isula pull 3laho3y3.mirror.aliyuncs.com/library/busybox"

    rm -f /etc/isulad/daemon.json.bak
    cp /etc/isulad/daemon.json /etc/isulad/daemon.json.bak

    sed -i "s/https/http/g" /etc/isulad/daemon.json
    check_valgrind_log
    fn_check_eq "$?" "0" "stop isulad with check valgrind"

    start_isulad_with_valgrind
    fn_check_eq "$?" "0" "start isulad with valgrind"

    isula pull busybox
    fn_check_eq "$?" "0" "isula pull busybox"

    rm -f /etc/isulad/daemon.json
    cp /etc/isulad/daemon.json.bak /etc/isulad/daemon.json
    rm -f /etc/isulad/daemon.json.bak

    isula rmi 3laho3y3.mirror.aliyuncs.com/library/busybox

    check_valgrind_log
    fn_check_eq "$?" "0" "stop isulad with check valgrind"

    start_isulad_with_valgrind
    fn_check_eq "$?" "0" "start isulad with valgrind"
}

function isula_login()
{
    isula login -u test -p test 3laho3y3.mirror.aliyuncs.com
    fn_check_eq "$?" "0" "isula login -u test -p test 3laho3y3.mirror.aliyuncs.com"

    # double login for memory leak check
    isula login -u test -p test 3laho3y3.mirror.aliyuncs.com
    fn_check_eq "$?" "0" "isula login -u test -p test 3laho3y3.mirror.aliyuncs.com"

    # use username/password to pull busybox for memmory leak check
    isula pull busybox
    fn_check_eq "$?" "0" "isula pull busybox"
}

function isula_logout()
{
    isula logout 3laho3y3.mirror.aliyuncs.com
    fn_check_eq "$?" "0" "isula logout 3laho3y3.mirror.aliyuncs.com"

    # double logout for memory leak check
    isula logout 3laho3y3.mirror.aliyuncs.com
    fn_check_eq "$?" "0" "isula logout 3laho3y3.mirror.aliyuncs.com"
}

function do_test_t()
{
    isula_pull
    isula_login
    isula_logout

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    cat $ISUALD_LOG
    let "ret=$ret + 1"
fi

show_result $ret "basic registry"
