#!/bin/bash
#
# attributes: isulad basic port
# concurrent: NA
# spend time: 15

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
##- @Author: haozi007
##- @Create: 2020-12-29
#######################################################################
curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function do_check_network_setting_ports()
{
    if [ "x$2" != "x" ]; then
        isula inspect -f '{{.NetworkSettings.Ports}}' $1 | grep $2
        fn_check_eq "$?" "0" "inspect container failed"
    fi
    if [ "x$3" != "x" ]; then
        isula inspect -f '{{.NetworkSettings.Ports}}' $1 | grep "HostIP" | grep $3
        fn_check_eq "$?" "0" "inspect container failed"
    fi
    if [ "x$4" != "x" ]; then
        isula inspect -f '{{.NetworkSettings.Ports}}' $1 | grep "HostPort" | grep $4
        fn_check_eq "$?" "0" "inspect container failed"
    fi
}

function test_port()
{
    local ret=0
    local containername=test_create

    msg_info "${test} starting..."

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula network create cni0
    fn_check_eq "$?" "0" "create network failed"

    isula run -itd --net cni0 -p 8080:80 --name $containername busybox
    fn_check_eq "$?" "0" "create container failed"
    testcontainer $containername running
    isula port $containername | grep "80/tcp -> 0.0.0.0:8080"
    fn_check_eq "$?" "0" "port failed"
    isula inspect -f '{{.NetworkSettings.Ports}}' $containername | grep HostPort | grep 8080
    fn_check_eq "$?" "0" "inspect container failed"
    isula stop -t 0 $containername
    fn_check_eq "$?" "0" "stop failed"
    isula rm $containername
    fn_check_eq "$?" "0" "rm failed"

    id=`isula run -tid --net cni0 --expose 80-83 -P busybox /bin/sh`
    fn_check_eq "$?" "0" "create container failed"
    testcontainer $id running
    count=`isula port $id | wc -l`
    fn_check_eq "$count" "4" "port required 4, get: $count"
    isula port $id | grep "80/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "81/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "82/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "83/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    do_check_network_setting_ports "$id" "80/tcp" "0.0.0.0"
    do_check_network_setting_ports "$id" "81/tcp" "0.0.0.0"
    do_check_network_setting_ports "$id" "82/tcp" "0.0.0.0"
    do_check_network_setting_ports "$id" "83/tcp" "0.0.0.0"
    isula stop -t 0 $id
    fn_check_eq "$?" "0" "stop failed"
    isula rm $id
    fn_check_eq "$?" "0" "rm failed"

    id=`isula run -tid --net cni0 -p 80-83 busybox /bin/sh`
    fn_check_eq "$?" "0" "create container failed"
    testcontainer $id running
    count=`isula port $id | wc -l`
    fn_check_eq "$count" "4" "port required 4, get: $count"
    isula port $id | grep "80/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "81/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "82/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "83/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    do_check_network_setting_ports "$id" "80/tcp" "0.0.0.0"
    do_check_network_setting_ports "$id" "81/tcp" "0.0.0.0"
    do_check_network_setting_ports "$id" "82/tcp" "0.0.0.0"
    do_check_network_setting_ports "$id" "83/tcp" "0.0.0.0"isula stop -t 0 $id
    fn_check_eq "$?" "0" "stop failed"
    isula rm $id
    fn_check_eq "$?" "0" "rm failed"

    id=`isula run -tid --net cni0 -p 127.0.0.1:80-82:90-92 busybox /bin/sh`
    fn_check_eq "$?" "0" "create container failed"
    testcontainer $id running
    count=`isula port $id | wc -l`
    fn_check_eq "$count" "3" "port required 3, get: $count"
    isula port $id | grep "90/tcp -> 127.0.0.1:80"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "91/tcp -> 127.0.0.1:81"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "92/tcp -> 127.0.0.1:82"
    fn_check_eq "$?" "0" "port failed"
    do_check_network_setting_ports "$id" "90/tcp" "127.0.0.1" "80"
    do_check_network_setting_ports "$id" "91/tcp" "127.0.0.1" "81"
    do_check_network_setting_ports "$id" "92/tcp" "127.0.0.1" "82"isula stop -t 0 $id
    fn_check_eq "$?" "0" "stop failed"
    isula rm $id
    fn_check_eq "$?" "0" "rm failed"

    id=`isula run -tid --net cni0 --expose 80-81 -P -p 8080:90 -p 91-92 busybox /bin/sh`
    fn_check_eq "$?" "0" "create container failed"
    testcontainer $id running
    count=`isula port $id | wc -l`
    fn_check_eq "$count" "5" "port required 5, get: $count"
    isula port $id | grep "90/tcp -> 0.0.0.0:8080"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "91/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "92/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "80/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    isula port $id | grep "81/tcp -> 0.0.0.0"
    fn_check_eq "$?" "0" "port failed"
    do_check_network_setting_ports "$id" "80/tcp" "0.0.0.0"
    do_check_network_setting_ports "$id" "81/tcp" "0.0.0.0"
    do_check_network_setting_ports "$id" "90/tcp" "0.0.0.0" "8080"
    do_check_network_setting_ports "$id" "91/tcp" "0.0.0.0"
    do_check_network_setting_ports "$id" "92/tcp" "0.0.0.0"
    isula stop -t 0 $id
    fn_check_eq "$?" "0" "stop failed"
    isula rm $id
    fn_check_eq "$?" "0" "rm failed"

    isula port xxxx
    fn_check_ne "$?" "0" "port expect failed"

    isula rm -f `isula ps -aq`

    isula network rm cni0
    fn_check_eq "$?" "0" "rm network failed"

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

test_port || ((ans++))

show_result ${ans} "${curr_path}/${0}"