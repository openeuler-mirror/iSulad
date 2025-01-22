#!/bin/bash
#
# attributes: isulad cri inspect ip
# concurrent: NA
# spend time: 46

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/criconfigs)
pause_img_path=$(realpath $curr_path/test_data)
pod_config="sandbox-config.json"
source ../helpers.sh

function do_pre()
{
    init_cri_conf $1
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to init cri conf: ${1}" && return ${FAILURE}

    init_cni_conf $data_path
    if [ $? -ne 0 ]; then
        msg_err "Failed to init cni config"
        TC_RET_T=$(($TC_RET_T+1))
        return $TC_RET_T
    fi
}

function do_post()
{
    local ret=0
    restore_cri_conf
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restore cri conf" && ((ret++))
    return $ret
}

function do_test()
{
    msg_info "this is $0 do_test -> ($1)"

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

    pod_id=`crictl runp --runtime $1 ${data_path}/$pod_config`
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

    cat ${RUNTIME_ROOT_PATH}/${1}/${pod_id}/network_settings.json | grep "$ip"
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


ans=0

for version in ${CRI_LIST[@]};
do
    test="test_cri_default_namespace_fun, use cri version => (${version})"
    msg_info "${test} starting..."

    do_pre $version || ((ans++))
    if [ $? -ne 0 ];then
        let "ans=$ans + 1"
    fi

    for element in ${RUNTIME_LIST[@]};
    do
        do_test $element
        if [ $? -ne 0 ];then
            let "ans=$ans + 1"
        fi
    done

    do_post || ((ans++))

    msg_info "${test} finished with return ${ans}..."
done

show_result $ans "cni base test"
