#!/bin/bash
#
# attributes: isulad cri pod default namespace
# concurrent: NA
# spend time: 10

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/criconfigs)
pause_img_path=$(realpath $curr_path/test_data)
source ../helpers.sh

function set_up()
{
    local ret=0
    local image="busybox"
    local podimage="mirrorgooglecontainers/pause-amd64"
    local test="set_up => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    init_cri_conf $1
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to init cri conf: ${1}" && return ${FAILURE}

    crictl pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    crictl images | grep ${podimage}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${podimage}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function test_cri_default_namespace_in_pod_fun()
{
    local ret=0
    local runtime=$1
    local test="test_cri_default_namespace_in_pod_fun => (${runtime})"
    msg_info "${test} starting..."

    sid=$(crictl runp --runtime $runtime ${data_path}/sandbox-config.json)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run sandbox" && ((ret++))

    cid=$(crictl create $sid ${data_path}/container-config-default-namespace.json ${data_path}/sandbox-config.json)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container" && ((ret++))

    crictl start $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start container" && ((ret++))

    spid=$(isula inspect -f '{{.State.Pid}}' $sid)
    cpid=$(isula inspect -f '{{.State.Pid}}' $cid)

    shared_namespace=(net ipc uts user)
    not_shared_namespace=(pid mnt)

    for element in ${shared_namespace[@]}; do
        sandboxns=$(ls /proc/$spid/ns -l | grep $element | awk -F "> " '{print $NF}')
        conatainerns=$(ls /proc/$cpid/ns -l | grep $element | awk -F "> " '{print $NF}')
        [[ x"$sandboxns" != x"$conatainerns" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - $element namespace should be shared in pod" && ((ret++))
    done

    for element in ${not_shared_namespace[@]}; do
        sandboxns=$(ls /proc/$spid/ns -l | grep $element | awk -F "> " '{print $NF}')
        conatainerns=$(ls /proc/$cpid/ns -l | grep $element | awk -F "> " '{print $NF}')
        [[ x"$sandboxns" == x"$conatainerns" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - $element namespace should be not shared in pod" && ((ret++))
    done

    crictl stop $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop container" && ((ret++))

    crictl rm $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container" && ((ret++))

    crictl stopp $sid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop sandbox" && ((ret++))

    crictl rmp $sid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm sandbox" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function tear_down()
{
    local ret=0
    restore_cri_conf
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restore cri conf" && ((ret++))
    return $ret
}

declare -i ans=0

for version in ${CRI_LIST[@]};
do
    test="test_cri_default_namespace_in_pod_fun, use cri version => (${version})"
    msg_info "${test} starting..."

    set_up $version || ((ans++))

    for element in ${RUNTIME_LIST[@]};
    do
        test_cri_default_namespace_in_pod_fun $element || ((ans++))
    done

    tear_down || ((ans++))
    msg_info "${test} finished with return ${ans}..."
done

show_result ${ans} "${curr_path}/${0}"
