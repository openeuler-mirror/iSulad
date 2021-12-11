#!/bin/bash
#
# attributes: isulad cri cni
# concurrent: NA
# spend time: 46

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath "$curr_path"/criconfigs)
pause_img_path=$(realpath "$curr_path"/test_data)
source ../helpers.sh

function do_pre() {
    cp /etc/isulad/daemon.json /etc/isulad/daemon.bak
    sed -i "s#\"pod-sandbox-image\": \"\"#\"pod-sandbox-image\": \"mirrorgooglecontainers/pause-amd64:3.0\"#g" /etc/isulad/daemon.json

    init_cni_conf "$data_path"
    if [ $? -ne 0 ]; then
        msg_err "Failed to init cni config"
        TC_RET_T=$(($TC_RET_T + 1))
        return $TC_RET_T
    fi

    isula load -i "${pause_img_path}"/pause.tar
    if [ $? -ne 0 ]; then
        msg_err "Failed to load pause image"
        TC_RET_T=$(($TC_RET_T + 1))
        return $TC_RET_T
    fi

}

function do_post() {
    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    check_valgrind_log
    start_isulad_with_valgrind
}

function do_test_help() {
    msg_info "this is $0 do_test"

    crictl pull busybox
    if [ $? -ne 0 ]; then
        msg_err "Failed to pull busybox image"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl images | grep "mirrorgooglecontainers/pause-amd64"
    if [ $? -ne 0 ]; then
        msg_err "Failed to find mirrorgooglecontainers/pause-amd64 image"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    sid=$(crictl runp "${data_path}"/"$1")
    if [ $? -ne 0 ]; then
        msg_err "Failed to run sandbox"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    spid=$(isula inspect -f '{{json .State.Pid}}' "$sid")
    nsenter -t "$spid" -n ifconfig eth0
    if [ $? -ne 0 ]; then
        msg_err "Sandbox network config failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    cid=$(crictl create "$sid" "${data_path}"/container-config.json "${data_path}"/"$1")
    if [ $? -ne 0 ]; then
        msg_err "create container failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl start "$cid"
    if [ $? -ne 0 ]; then
        msg_err "start container failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl stats
    if [ $? -ne 0 ]; then
        msg_err "stats container failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    # check whether container use pod network namespace
    pod_pid=$(isula inspect -f '{{json .State.Pid}}' "$sid")
    pod_net_ns_id=$(ls -l /proc/"${pod_pid}"/ns/net | awk -F[ '{print $2}' | awk -F] '{print $1}')
    con_pid=$(isula inspect -f '{{json .State.Pid}}' "$cid")
    con_net_ns_id=$(ls -l /proc/"${con_pid}"/ns/net | awk -F[ '{print $2}' | awk -F] '{print $1}')

    if [ "$pod_net_ns_id" != "$con_net_ns_id" ]; then
        msg_err "Pod and container use different network namespace"
        nsenter -t "$pod_pid" -n ifconfig eth0
        nsenter -t "$con_pid" -n ifconfig eth0
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    nsenter -t "$pod_pid" -n ifconfig eth0 | grep "$2"
    if [ $? -ne 0 ]; then
        msg_err "expect ip: $1, get: "
        nsenter -t "$pod_pid" -n ifconfig eth0
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    crictl inspectp "$sid" | grep "$2"
    if [ $? -ne 0 ]; then
        msg_err "inspectp: expect ip: $1, get: "
        crictl inspectp "$sid"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    if [ "x$3" != "x" ]; then
        nsenter -t "$pod_pid" -n ifconfig eth1 | grep "$3"
        if [ $? -ne 0 ]; then
            msg_err "expect ip: $2, get: "
            nsenter -t "$pod_pid" -n ifconfig eth1
            TC_RET_T=$(($TC_RET_T + 1))
        fi
        crictl inspectp "$sid" | grep "$3"
        if [ $? -ne 0 ]; then
            msg_err "inspectp expect ip: $2, get: "
            crictl inspectp "$sid"
            TC_RET_T=$(($TC_RET_T + 1))
        fi
    fi

    crictl stop "$cid"
    if [ $? -ne 0 ]; then
        msg_err "stop container failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl rm "$cid"
    if [ $? -ne 0 ]; then
        msg_err "stop container failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl stopp "$sid"
    if [ $? -ne 0 ]; then
        msg_err "stop sandbox failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl rmp "$sid"
    if [ $? -ne 0 ]; then
        msg_err "rm sandbox failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    return $TC_RET_T
}

function default_cni_config() {
    do_test_help "sandbox-config.json" "10\.1\."
}

function new_cni_config() {
    cp "${data_path}"/bridge.json /etc/cni/net.d/
    sync
    sync
    tail "$ISUALD_LOG"
    # wait cni updated
    s=$(date "+%s")
    for ((i = 0; i < 30; i++)); do
        sleep 1
        cur=$(date "+%s")
        let "t=cur-s"
        if [ "$t" -gt 6 ]; then
            break
        fi
    done
    tail "$ISUALD_LOG"
    do_test_help "mutlnet_pod.json" "10\.2\." "10\.1\."
}

function check_annotation() {
    rm -f /etc/cni/net.d/*
    cp "${data_path}"/mock.json /etc/cni/net.d/bridge.json
    sync
    sync
    tail "$ISUALD_LOG"
    # wait cni updated
    s=$(date "+%s")
    for ((i = 0; i < 30; i++)); do
        sleep 1
        cur=$(date "+%s")
        let "t=cur-s"
        if [ "$t" -gt 6 ]; then
            break
        fi
    done
    tail "$ISUALD_LOG"

    sid=$(crictl runp "${data_path}"/sandbox-config.json)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run sandbox"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    basepath=/tmp/cnilogs/
    cat ${basepath}/"${sid}"_eth0.env | grep CNI_MUTLINET_EXTENSION
    if [ $? -ne 0 ]; then
        msg_err "lost extension for mutl network args"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    cat ${basepath}/"${sid}"_eth0.env | grep "extension=first"
    if [ $? -ne 0 ]; then
        msg_err "lost extension for first cni args"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    cat ${basepath}/"${sid}"_eth0.env | grep "extension=second"
    if [ $? -eq 0 ]; then
        msg_err "same extension key write to cni args"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl stopp "$sid"
    if [ $? -ne 0 ]; then
        msg_err "stop sandbox failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl rmp "$sid"
    if [ $? -ne 0 ]; then
        msg_err "rm sandbox failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    return $TC_RET_T
}

function check_rollback() {
    rm -f /etc/cni/net.d/*
    cp "${data_path}"/mock.json /etc/cni/net.d/bridge.json
    sed -i "s#mock#default#g" /etc/cni/net.d/bridge.json
    cp "${data_path}"/mock.json /etc/cni/net.d/
    cp "${data_path}"/mock_wrong.json /etc/cni/net.d/
    sync
    sync
    tail "$ISUALD_LOG"
    # wait cni updated
    s=$(date "+%s")
    for ((i = 0; i < 30; i++)); do
        sleep 1
        cur=$(date "+%s")
        let "t=cur-s"
        if [ "$t" -gt 6 ]; then
            break
        fi
    done
    tail "$ISUALD_LOG"

    crictl runp "${data_path}"/mutl_wrong_net_pod.json
    if [ $? -eq 0 ]; then
        msg_err "Run sandbox success with invalid cni configs"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    sid=$(crictl pods -q | head -1)

    basepath=/tmp/cnilogs/

    cat ${basepath}/"${sid}"_eth0.env | grep "CNI_COMMAND=DEL"
    if [ $? -ne 0 ]; then
        msg_err "do not rollback for eth0"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    cat ${basepath}/"${sid}"_eth1.env | grep "CNI_COMMAND=DEL"
    if [ $? -ne 0 ]; then
        msg_err "do not rollback for eth1"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    cat ${basepath}/"${sid}"_eth2.env | grep "CNI_COMMAND=DEL"
    if [ $? -ne 0 ]; then
        msg_err "do not rollback for eth2"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl stopp "$sid"
    if [ $? -ne 0 ]; then
        msg_err "stop sandbox failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    crictl rmp "$sid"
    if [ $? -ne 0 ]; then
        msg_err "rm sandbox failed"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    rm -f /etc/cni/net.d/*
    cp "${data_path}"/bridge.json /etc/cni/net.d/

    return $TC_RET_T
}

ret=0

do_pre
if [ $? -ne 0 ]; then
    let "ret=$ret + 1"
fi

default_cni_config
if [ $? -ne 0 ]; then
    let "ret=$ret + 1"
fi

new_cni_config
if [ $? -ne 0 ]; then
    let "ret=$ret + 1"
fi

check_annotation
if [ $? -ne 0 ]; then
    let "ret=$ret + 1"
fi

check_rollback
if [ $? -ne 0 ]; then
    let "ret=$ret + 1"
fi

do_post

show_result "$ret" "cni base test"
