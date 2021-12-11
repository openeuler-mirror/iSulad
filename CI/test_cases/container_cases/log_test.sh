#!/bin/bash
#
# attributes: isulad container log
# concurrent: NA
# spend time: 46

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath "$curr_path"/test_data)
source ../helpers.sh

function do_pre() {
    mv /etc/isulad/daemon.json /etc/isulad/daemon.bak
    cp "${data_path}"/daemon.json /etc/isulad/daemon.json
    TC_RET_T=0
}

function do_post() {
    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    check_valgrind_log
    start_isulad_with_valgrind
}

function do_check_item() {
    cat "${ISULAD_ROOT_PATH}"/engines/lcr/"$1"/config | grep console | grep "$2"
    if [ $? -ne 0 ]; then
        cat "${ISULAD_ROOT_PATH}"/engines/lcr/"$1"/config | grep console
        msg_err "expect $2"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
}

function do_test_syslog_helper() {
    msg_info "this is $0 do_test"

    crictl pull busybox
    if [ $? -ne 0 ]; then
        msg_err "Failed to pull busybox image"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    cid=$(isula run -tid busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    do_check_item "${cid}" "logdriver = syslog"

    if [ "x$1" != "x" ]; then
        do_check_item "${cid}" "syslog_tag = $1"
    fi

    isula rm -f "${cid}"
    if [ $? -ne 0 ]; then
        msg_err "Failed to remove container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    return $TC_RET_T
}

function do_test_syslog_tag() {
    local cid
    msg_info "this is $0 do_test"

    crictl pull busybox
    if [ $? -ne 0 ]; then
        msg_err "Failed to pull busybox image"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    isula run -ti --log-opt="syslog-tag={{.xxx}}" busybox date
    if [ $? -eq 0 ]; then
        msg_err "run container success with invalid syslog-tag"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    isula run -ti --log-opt="syslog-tag={{" busybox date
    if [ $? -eq 0 ]; then
        msg_err "run container success with invalid syslog-tag"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    isula run -ti --log-opt="syslog-tag=aab{{cd" busybox date
    if [ $? -eq 0 ]; then
        msg_err "run container success with invalid syslog-tag"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    cid=$(isula run -tid --log-opt="syslog-tag={{.DaemonName}}" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = syslog"
    do_check_item "${cid}" "syslog_tag = iSulad"

    cid=$(isula run -tid --log-opt="syslog-tag={{.ID}}" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = syslog"
    do_check_item "${cid}" "syslog_tag = ${cid:0:12}"

    cid=$(isula run -tid --name=haozi --log-opt="syslog-tag={{.ID}}xx{{.Name}}" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = syslog"
    do_check_item "${cid}" "syslog_tag = ${cid:0:12}xxhaozi"
    isula rm -f haozi

    cid=$(isula run -tid --log-opt="syslog-tag={{.FullID}}" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = syslog"
    do_check_item "${cid}" "syslog_tag = ${cid}"

    cid=$(isula run -tid --name haozi --log-opt="syslog-tag={{.Name}}" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = syslog"
    do_check_item "${cid}" "syslog_tag = haozi"
    isula rm -f haozi

    cid=$(isula run -tid --name haozi --log-opt="syslog-tag=xx{{.Name}}yy" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = syslog"
    do_check_item "${cid}" "syslog_tag = xxhaoziyy"
    isula rm -f haozi

    cid=$(isula run -tid --log-opt="syslog-tag={{.ImageName}}" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = syslog"
    do_check_item "${cid}" "syslog_tag = busybox"

    cid=$(isula run -tid --log-opt="syslog-tag={{.ImageID}}" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    img_id=$(isula inspect -f '{{.image.id}}' busybox)
    do_check_item "${cid}" "logdriver = syslog"
    do_check_item "${cid}" "syslog_tag = sha256:${img_id:0:5}"

    isula rm -f $(isula ps -aq)
    if [ $? -ne 0 ]; then
        msg_err "Failed to remove container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    return $TC_RET_T
}

function do_test_json_file_helper() {
    msg_info "this is $0 do_test"
    local file_cnt=7
    local file_size=1MB

    if [ "x$1" != "x" ]; then
        file_cnt=$1
    fi
    if [ "x$2" != "x" ]; then
        file_size=$2
    fi

    cid=$(isula run -tid busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    do_check_item "${cid}" "logdriver = json-file"
    do_check_item "${cid}" "rotate = $file_cnt"
    do_check_item "${cid}" "size = $file_size"

    isula rm -f "${cid}"
    if [ $? -ne 0 ]; then
        msg_err "Failed to remove container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    return $TC_RET_T
}

function do_test_container_log() {
    msg_info "this is $0 do_test"
    cat /etc/isulad/daemon.json
    ps aux | grep -i isulad

    cid=$(isula run -tid --log-driver=json-file busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = json-file"
    do_check_item "${cid}" "rotate = 7"
    do_check_item "${cid}" "size = 1MB"

    cid=$(isula run -tid --log-driver=json-file --log-opt="max-file=8" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = json-file"
    do_check_item "${cid}" "rotate = 8"
    do_check_item "${cid}" "size = 1MB"

    cid=$(isula run -tid --log-driver=json-file --log-opt="max-size=128KB" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    do_check_item "${cid}" "logdriver = json-file"
    do_check_item "${cid}" "rotate = 7"
    do_check_item "${cid}" "size = 128KB"

    cid=$(isula run -tid --log-driver=json-file --log-opt="disable-log=true" busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T + 1))
    fi
    cat "${ISULAD_ROOT_PATH}"/engines/lcr/"${cid}"/config | grep console | grep "logfile ="
    if [ $? -eq 0 ]; then
        msg_err "Failed to disable log"
        TC_RET_T=$(($TC_RET_T + 1))
    fi

    isula rm -f $(isula ps -aq)
    return $TC_RET_T
}

function do_test_container_syslog() {
    do_test_syslog_helper "xxxx"

    do_test_syslog_tag
}

function do_test() {
    check_valgrind_log
    start_isulad_with_valgrind --container-log-opts="syslog-tag=xxxx"

    do_test_container_syslog

    check_valgrind_log
    start_isulad_with_valgrind --container-log-driver=json-file --container-log-opts="max-size=10MB" --container-log-opts="max-file=3"
    do_test_json_file_helper "3" "10MB"

    check_valgrind_log
    start_isulad_with_valgrind
    do_test_container_log
}

ret=0

do_pre

do_test

do_post

show_result $TC_RET_T "container log test"
