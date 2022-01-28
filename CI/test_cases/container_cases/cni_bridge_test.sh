#!/bin/bash
#
# attributes: isulad cri cni
# concurrent: NA
# spend time: 52

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description: CI test case for cni bridge feature.
#                 It will create and start two pods, then pods ping
#                 each other. The expected behavior is that packets can be
#                 detected on cni0 by tcpdump. 
##- @Author: chengzeruizhi
##- @Create: 2021-11-30
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/criconfigs)
pause_img_path=$(realpath $curr_path/test_data)
source ../helpers.sh
timeout_count_down=10
ping_count_down=5

function do_pre()
{
    local ret=0
    
    cp /etc/isulad/daemon.json /etc/isulad/daemon.bak
    sed -i "s#\"pod-sandbox-image\": \"\"#\"pod-sandbox-image\": \"mirrorgooglecontainers/pause-amd64:3.0\"#g" /etc/isulad/daemon.json

    init_cni_conf $data_path
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to init cni config" && ((ret++))

    rm -rf /etc/cni/net.d/*
    cp ${data_path}/bridge.json /etc/cni/net.d/
    sync;sync;
    tail $ISUALD_LOG
    # wait cni updated
    s=`date "+%s"`
    for ((i=0;i<30;i++)); do
        sleep 1
        cur=`date "+%s"`
        let "t=cur-s"
        if [ $t -gt 6 ];then
            break
        fi
    done
    tail $ISUALD_LOG

    isula load -i ${pause_img_path}/pause.tar
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to load pause image" && ((ret++))
    
    msg_info "$0 do_pre finished with return ${ret}..."
    return ${ret}
}

function do_post()
{
    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    check_valgrind_log
    start_isulad_with_valgrind
}

function do_test_help()
{
    local ret=0

    msg_info "this is $0 do_test"

    crictl pull busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to pull busybox image" && ((ret++))

    crictl images | grep "mirrorgooglecontainers/pause-amd64"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to find mirrorgooglecontainers/pause-amd64 image" && ((ret++))

    sid1=`crictl runp ${data_path}/$1`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to run sandbox1" && ((ret++))

    spid1=`isula inspect -f '{{json .State.Pid}}' $sid1`
    nsenter -t $spid1 -n ifconfig eth0
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Sandbox1 network config failed" && ((ret++))

    sid2=`crictl runp ${data_path}/$2`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to run sandbox2" && ((ret++))

    spid2=`isula inspect -f '{{json .State.Pid}}' $sid2`
    nsenter -t $spid2 -n ifconfig eth0
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Sandbox network2 config failed" && ((ret++))

    pod_pid1=`isula inspect -f '{{json .State.Pid}}' $sid1`
    pod_pid2=`isula inspect -f '{{json .State.Pid}}' $sid2`

    nsenter -t $pod_pid1 -n ifconfig eth0 | grep "$3"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - expect ip: $3, get: " && ((ret++))

    crictl inspectp $sid1 | grep "$3"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspectp: expect ip: $3, get: " && ((ret++))

    nsenter -t $pod_pid2 -n ifconfig eth0 | grep "$3"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - expect ip: $3, get: " && ((ret++))

    crictl inspectp $sid2 | grep "$3"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspectp: expect ip: $3, get: " && ((ret++))

    ip2=`crictl inspectp $sid2 | grep -w ip | awk '{print $2}' | sed 's/\"//g'`
    nsenter --net=/proc/$pod_pid1/ns/net ping -w $timeout_count_down -c $ping_count_down $ip2 & 
    timeout $timeout_count_down tcpdump -c $ping_count_down -i cni0
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ping another pod failed" && ((ret++))

    wait$!

    crictl stopp $sid1 $sid2
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop sandbox failed" && ((ret++))

    crictl rmp $sid1 $sid2
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm sandbox failed" && ((ret++))

    msg_info "$0 do_test finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

do_pre || ((ans++))

do_test_help "sandbox-config.json" "sandbox-config2.json" "10\.2\." || ((ans++))

do_post

show_result ${ans} "${curr_path}/${0}"