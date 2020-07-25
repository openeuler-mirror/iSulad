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
source ../helpers.bash

function isula_pull()
{
    isula rm -f `isula ps -a -q`
    isula rmi busybox

    for i in `seq 1 10`
    do
        isula pull busybox &
    done
    isula pull busybox
    fn_check_eq "$?" "0" "isula pull busybox"
    wait

    isula inspect busybox
    fn_check_eq "$?" "0" "isula inspect busybox"

    isula pull hub-mirror.c.163.com/library/busybox
    fn_check_eq "$?" "0" "isula pull hub-mirror.c.163.com/library/busybox"

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

    check_valgrind_log
    fn_check_eq "$?" "0" "stop isulad with check valgrind"

    start_isulad_with_valgrind
    fn_check_eq "$?" "0" "start isulad with valgrind"
}

function isula_login()
{
    isula login -u test -p test hub-mirror.c.163.com
    fn_check_eq "$?" "0" "isula login -u test -p test hub-mirror.c.163.com"

    # double login for memory leak check
    isula login -u test -p test hub-mirror.c.163.com
    fn_check_eq "$?" "0" "isula login -u test -p test hub-mirror.c.163.com"

    # use username/password to pull busybox for memmory leak check
    isula pull busybox
    fn_check_eq "$?" "0" "isula pull busybox"
}

function isula_logout()
{
    isula logout hub-mirror.c.163.com
    fn_check_eq "$?" "0" "isula logout hub-mirror.c.163.com"

    # double logout for memory leak check
    isula logout hub-mirror.c.163.com
    fn_check_eq "$?" "0" "isula logout hub-mirror.c.163.com"
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
