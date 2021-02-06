#!/bin/bash
#
# attributes: isulad cri inspect ip
# concurrent: NA
# spend time: 46

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/criconfigs)
pause_img_path=$(realpath $curr_path/test_data)
work_path="/var/lib/isulad/engines/lcr"
pod_config="sandbox-config.json"
source ../helpers.sh

function do_pre()
{
    cp /etc/isulad/daemon.json /etc/isulad/daemon.bak
    sed -i "s#\"pod-sandbox-image\": \"\"#\"pod-sandbox-image\": \"mirrorgooglecontainers/pause-amd64:3.0\"#g" /etc/isulad/daemon.json

    init_cni_conf $data_path
    if [ $? -ne 0 ]; then
        msg_err "Failed to init cni config"
        TC_RET_T=$(($TC_RET_T+1))
        return $TC_RET_T
    fi

    isula load -i ${pause_img_path}/pause.tar
    if [ $? -ne 0 ]; then
        msg_err "Failed to load pause image"
        TC_RET_T=$(($TC_RET_T+1))
        return $TC_RET_T
    fi

}

function do_post()
{
    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    check_valgrind_log
    start_isulad_with_valgrind
}

function do_test()
{
    msg_info "this is $0 do_test"

    crictl pull busybox
    if [ $? -ne 0 ]; then
        msg_err "Failed to pull busybox image"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    crictl images | grep "mirrorgooglecontainers/pause-amd64"
    if [ $? -ne 0 ]; then
        msg_err "Failed to find mirrorgooglecontainers/pause-amd64 image"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    pod_id=`crictl runp ${data_path}/$pod_config`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run sandbox"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    isula inspect $pod_id

    ip=`isula inspect -f "{{json .NetworkSettings.Networks.good.IPAddress}}" $pod_id`
    if [ $? -ne 0 ]; then
        msg_err "Failed to inspect pod ip"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    # delete \r \n and other charactors
    ip=`echo $ip | awk -F'"' '{print $2}'`

    pod_pid=`isula inspect -f '{{json .State.Pid}}' $pod_id`
    if [ $? -ne 0 ];then
        msg_err "Get sandbox pod pid failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    nsenter -t $pod_pid -n ifconfig eth0 | grep "$ip"
    if [ $? -ne 0 ];then
        msg_err "expect ip: $ip, nsenter cannot get it"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    cat ${work_path}/${pod_id}/network_settings.json | grep "$ip"
    if [ $? -ne 0 ];then
        msg_err "expect ip: $ip, network_settings.json cannot get it"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    crictl stopp $pod_id
    if [ $? -ne 0 ];then
        msg_err "stop sandbox failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    crictl rmp $pod_id
    if [ $? -ne 0 ];then
        msg_err "rm sandbox failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    return $TC_RET_T
}


ret=0

do_pre
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

do_test
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

do_post

show_result $ret "cni base test"
