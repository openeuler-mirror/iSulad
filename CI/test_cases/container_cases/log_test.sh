#!/bin/bash
#
# attributes: isulad container log
# concurrent: NA
# spend time: 46

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/test_data)
source ../helpers.sh

function do_pre()
{
    mv /etc/isulad/daemon.json /etc/isulad/daemon.bak
    cp ${data_path}/daemon.json /etc/isulad/daemon.json
    TC_RET_T=0
}

function do_post()
{
    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    check_valgrind_log
    start_isulad_with_valgrind
}

function do_check_item()
{
    cat ${RUNTIME_ROOT_PATH}/$1/$2/config.json | grep console | grep "$3"
    if [ $? -ne 0 ]; then
        cat ${RUNTIME_ROOT_PATH}/$1/$2/config.json | grep console
        msg_err "expect $3"
        TC_RET_T=$(($TC_RET_T+1))
    fi
}

function do_test_syslog_helper()
{
    msg_info "this is $0 do_test"

    crictl pull busybox
    if [ $? -ne 0 ]; then
        msg_err "Failed to pull busybox image"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    cid=`isula run -tid --runtime $2 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    do_check_item $2 ${cid} "driver\": \"syslog"

    if [ "x$1" != "x" ]; then
        do_check_item $2 ${cid} "tag\": \"$1"
    fi

    isula rm -f ${cid}
    if [ $? -ne 0 ]; then
        msg_err "Failed to remove container"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    return $TC_RET_T
}

function do_test_syslog_tag()
{
    local cid
    msg_info "this is $0 do_test"

    crictl pull busybox
    if [ $? -ne 0 ]; then
        msg_err "Failed to pull busybox image"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula run -ti --log-opt="syslog-tag={{.xxx}}" --runtime $1 busybox date
    if [ $? -eq 0 ]; then
        msg_err "run container success with invalid syslog-tag"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula run -ti --log-opt="syslog-tag={{" --runtime $1 busybox date
    if [ $? -eq 0 ]; then
        msg_err "run container success with invalid syslog-tag"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula run -ti --log-opt="syslog-tag=aab{{cd" --runtime $1 busybox date
    if [ $? -eq 0 ]; then
        msg_err "run container success with invalid syslog-tag"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    cid=$(isula run -tid --log-opt="syslog-tag={{.DaemonName}}" --runtime $1 busybox sh)
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"syslog"
    do_check_item $1 ${cid} "tag\": \"iSulad"

    cid=`isula run -tid --log-opt="syslog-tag={{.ID}}" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"syslog"
    do_check_item $1 ${cid} "tag\": \"${cid: 0: 12}"

    cid=`isula run -tid --name=haozi --log-opt="syslog-tag={{.ID}}xx{{.Name}}" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"syslog"
    do_check_item $1 ${cid} "tag\": \"${cid: 0: 12}xxhaozi"
    isula rm -f haozi

    cid=`isula run -tid --log-opt="syslog-tag={{.FullID}}" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"syslog"
    do_check_item $1 ${cid} "tag\": \"${cid}"

    cid=`isula run -tid --name haozi --log-opt="syslog-tag={{.Name}}" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"syslog"
    do_check_item $1 ${cid} "tag\": \"haozi"
    isula rm -f haozi

    cid=`isula run -tid --name haozi --log-opt="syslog-tag=xx{{.Name}}yy" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"syslog"
    do_check_item $1 ${cid} "tag\": \"xxhaoziyy"
    isula rm -f haozi

    cid=`isula run -tid --log-opt="syslog-tag={{.ImageName}}" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"syslog"
    do_check_item $1 ${cid} "tag\": \"busybox"

    cid=`isula run -tid --log-opt="syslog-tag={{.ImageID}}" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    img_id=`isula inspect -f '{{.image.id}}' busybox`
    do_check_item $1 ${cid} "driver\": \"syslog"
    do_check_item $1 ${cid} "tag\": \"sha256:${img_id:0:5}"

    isula rm -f `isula ps -aq`
    if [ $? -ne 0 ]; then
        msg_err "Failed to remove container"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    return $TC_RET_T
}

function do_test_json_file_helper()
{
    msg_info "this is $0 do_test"
    local file_cnt=7
    local file_size=1MB

    if [ "x$1" != "x" ]; then
        file_cnt=$1
    fi
    if [ "x$2" != "x" ]; then
        file_size=$2
    fi

    cid=`isula run -tid --runtime $3 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    do_check_item $3 ${cid} "driver\": \"json-file"
    do_check_item $3 ${cid} "rotate\": \"$file_cnt"
    do_check_item $3 ${cid} "size\": \"$file_size"

    isula rm -f ${cid}
    if [ $? -ne 0 ]; then
        msg_err "Failed to remove container"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    return $TC_RET_T
}

function do_test_container_log()
{
    msg_info "this is $0 do_test"
    cat /etc/isulad/daemon.json
    ps aux | grep -i isulad

    cid=`isula run -tid --log-driver=json-file --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"json-file"
    do_check_item $1 ${cid} "rotate\": \"7"
    do_check_item $1 ${cid} "size\": \"1MB"

    cid=`isula run -tid --log-driver=json-file --log-opt="max-file=8" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"json-file"
    do_check_item $1 ${cid} "rotate\": \"8"
    do_check_item $1 ${cid} "size\": \"1MB"

    cid=`isula run -tid --log-driver=json-file --log-opt="max-size=128KB" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    do_check_item $1 ${cid} "driver\": \"json-file"
    do_check_item $1 ${cid} "rotate\": \"7"
    do_check_item $1 ${cid} "size\": \"128KB"

    cid=`isula run -tid --log-driver=json-file --log-opt="disable-log=true" --runtime $1 busybox sh`
    if [ $? -ne 0 ]; then
        msg_err "Failed to run container"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    cat ${RUNTIME_ROOT_PATH}/$1/$cid/config.json | grep console | grep "\"log.console.file\": \"none\""
    if [ $? -ne 0 ]; then
        msg_err "Failed to disable log"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula rm -f `isula ps -aq`
    return $TC_RET_T
}

function do_test_container_syslog() {
    do_test_syslog_helper "xxxx" $1

    do_test_syslog_tag $1
}

function do_test() {
    local runtime=$1
    local test="log_test => (${runtime})"
    msg_info "${test} starting..."

    check_valgrind_log
    start_isulad_with_valgrind --container-log-opts="syslog-tag=xxxx"

    do_test_container_syslog $runtime

    check_valgrind_log
    start_isulad_with_valgrind --container-log-driver=json-file --container-log-opts="max-size=10MB" --container-log-opts="max-file=3"
    
    do_test_json_file_helper "3" "10MB" $runtime

    check_valgrind_log
    start_isulad_with_valgrind

    do_test_container_log $runtime

    msg_info "${test} finished with return ${TC_RET_T}..."

    return $TC_RET_T
}

do_pre

ret=0

for element in ${RUNTIME_LIST[@]};
do
    do_test $element
    if [ $? -ne 0 ];then
        let "ret=$ret + 1"
    fi
done

do_post

show_result $ret "container log test"
