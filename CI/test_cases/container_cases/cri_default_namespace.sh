#!/bin/bash
#
# attributes: isulad cri pod default namespace
# concurrent: NA
# spend time: 10

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath "$curr_path"/criconfigs)
pause_img_path=$(realpath "$curr_path"/test_data)
source ../helpers.sh

function set_up() {
    local ret=0
    local image="busybox"
    local podimage="mirrorgooglecontainers/pause-amd64"
    local test="set_up => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    cp /etc/isulad/daemon.json /etc/isulad/daemon.bak
    sed -i "s#\"pod-sandbox-image\": \"\"#\"pod-sandbox-image\": \"mirrorgooglecontainers/pause-amd64:3.0\"#g" /etc/isulad/daemon.json

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop isulad" && return "${FAILURE}"

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start isulad" && return "${FAILURE}"

    isula load -i "${pause_img_path}"/pause.tar
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to load pause image" && return "${FAILURE}"

    crictl pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return "${FAILURE}"

    crictl images | grep ${podimage}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${podimage}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

function test_cri_default_namespace_in_pod_fun() {
    local ret=0
    local test="test_cri_default_namespace_in_pod_fun => (${FUNCNAME[@]})"
    msg_info "${test} starting..."

    sid=$(crictl runp "${data_path}"/sandbox-config.json)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run sandbox" && ((ret++))

    cid=$(crictl create "$sid" "${data_path}"/container-config-default-namespace.json "${data_path}"/sandbox-config.json)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container" && ((ret++))

    crictl start "$cid"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start container" && ((ret++))

    spid=$(isula inspect -f '{{.State.Pid}}' "$sid")
    cpid=$(isula inspect -f '{{.State.Pid}}' "$cid")

    shared_namespace=(net ipc uts user)
    not_shared_namespace=(pid mnt)

    for element in ${shared_namespace[@]}; do
        sandboxns=$(ls /proc/"$spid"/ns -l | grep "$element" | awk -F "> " '{print $NF}')
        conatainerns=$(ls /proc/"$cpid"/ns -l | grep "$element" | awk -F "> " '{print $NF}')
        [[ x"$sandboxns" != x"$conatainerns" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - $element namespace should be shared in pod" && ((ret++))
    done

    for element in ${not_shared_namespace[@]}; do
        sandboxns=$(ls /proc/"$spid"/ns -l | grep "$element" | awk -F "> " '{print $NF}')
        conatainerns=$(ls /proc/"$cpid"/ns -l | grep "$element" | awk -F "> " '{print $NF}')
        [[ "$sandboxns" == "$conatainerns" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - $element namespace should be not shared in pod" && ((ret++))
    done

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

function tear_down() {
    local ret=0

    crictl stop "$cid"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop container" && ((ret++))

    crictl rm "$cid"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container" && ((ret++))

    crictl stopp "$sid"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop sandbox" && ((ret++))

    crictl rmp "$sid"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm sandbox" && ((ret++))

    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    check_valgrind_log
    start_isulad_with_valgrind

    return "${ret}"
}

declare -i ans=0

set_up || ((ans++))

test_cri_default_namespace_in_pod_fun || ((ans++))

tear_down || ((ans++))

show_result "${ans}" "${curr_path}/${0}"
