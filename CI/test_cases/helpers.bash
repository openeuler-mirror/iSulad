#!/bin/bash

set -x

CRICTL=$(which crictl)

# testcase result
TC_RET_T=0

# image to pull and run container
BUSYBOX_IMAGE="busybox:latest"
valgrind_log="/tmp/valgrind.log"
ISUALD_LOG="/var/lib/isulad/isulad.log"
ISULAD_ROOT_DIR="/var/lib/isulad"
ISULAD_LCR_ENGINE_DIR="$ISULAD_ROOT_DIR/engines/lcr"
kubeAPIVersion="0.1.0"
iSulaRuntimeName="iSulad"
RuntimeVersion="2.0"
RuntimeAPIVersion="1.0"
Logging_Driver="json-file"
Cgroup_Driver="cgroupfs"

# ===================================================
function echo_text()
{
    local TXT=$1
    local COLOR=$2

    if [ "${COLOR}" = "red" ];then
        echo -e "\e[1;31m${TXT} \e[0m"
    elif [ "${COLOR}" = "green" ];then
        echo -e "\e[1;32m${TXT} \e[0m"
    elif [ "${COLOR}" = "yellow" ];then
        echo -e "\e[1;33m${TXT} \e[0m"
    else
        echo ${TXT}
    fi
}

function ERROR()
{
    txt_str=$1
    echo_text "$txt_str" red
}

function INFO()
{
    txt_str=$1
    echo_text "$txt_str" green
}

function DEBUG()
{
    txt_str=$1
    echo_text "$txt_str" yellow
}
# ===============================================

function is_new_oci_image() {
    ps aux | grep "isulad_kit" | grep "isula_image\.sock" > /dev/null 2>&1
    if [ $? -ne 0 ];then
        DEBUG "Current use old oci image mechanism, Skip this testcase......"
        exit 0
    fi
}

function check_fn_return() {
    if [[ "$1" != "$2" ]];then
        ERROR "[`date`] Expect '$1' but got '$2': FAILED ($3)"
        ((TC_RET_T++))
    else
        INFO "[`date`] Expect '$1' and got '$2': SUCCESS ($3)"
    fi
}

function check_fn_return_noskip() {
    if [[ "$1" != "$2" ]];then
        ERROR "[`date`] Expect '$1' but got '$2': FAILED ($3)"
        exit 1
    else
        INFO "[`date`] Expect '$1' and got '$2': SUCCESS ($3)"
    fi
}

function isulad_is_running() {
    local ret=1
    for i in `seq 3`;do
        isula version
        if [ $? -eq 0 ];then
            ret=0
            break
        fi
        sleep 1
    done
    return ${ret}
}

function wait_isulad_running() {
    echo "-------waiting iSulad running--------"
    waitcnt=0
    maxcnt=60
    while [ 0 ]
    do
        isula version
        if [ $? -eq 0 ];then
            break
        fi
        if [ $waitcnt -gt $maxcnt ];then
            echo "iSulad is not running after ${maxcnt}s"
            return 1
        fi
        waitcnt=$(($waitcnt+1))
        sleep 1
    done
    echo "--------iSulad is running-----------"
}

function start_isulad_with_valgrind() {
    valgrind --fair-sched=yes --log-file=$valgrind_log --tool=memcheck --leak-check=yes -v --track-origins=yes isulad $@ -l DEBUG >/dev/null 2>&1 &
    wait_isulad_running
}

function check_isulad_stopped() {
    maxtimes=15
    curcnt=0

    spid=$1
    while [ $curcnt -lt $maxtimes ]
    do
        ps aux | grep isulad | grep -v "grep" | grep -w $spid
        if [ $? -ne 0 ];then
            return 0
        fi
        let "curcnt=$curcnt + 1"
        sleep 1
    done
    return 1
}

function check_valgrind_log() {
    pid=`cat /var/run/isulad.pid`
    kill -15 $pid
    check_isulad_stopped $pid
    if [ $? -ne 0 ];then
        echo "Stop iSulad with valgrind failed"
        kill -9 $pid
        sleep 1
    fi

    cat $valgrind_log | grep "are definitely lost" | grep "==$pid=="
    if [ $? -eq 0 ];then
        echo "Memory leak may checked by valgrind, see valgrind log file: $valgrind_log"
        sed -n '/definitely lost/,// p' $valgrind_log
        exit 1
    fi
    return 0
}

# Wrapper for crictl
function crictl() {
    "$CRICTL" -i unix:///var/run/isulad.sock -r unix:///var/run/isulad.sock "$@"
}

function get_cgroup_real_path()
{
    cat /proc/1/cgroup | head -n 1 | awk -F ':' '{print $3}'
}

function get_container_interface_ip_by_pid() {
    if [ $# -ne 2 ];then
        return ""
    fi
    nsenter -t $1 -n ifconfig $2 | grep 'inet ' | sed 's/netmask.*//g' | grep -Eoe "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
}

function set_ip_for_cni_bridge() {
    if [ $# -ne 2 ];then
        echo "set_ip_for_cni_bridge: invalid arguments, usage: set_ip_for_cni_bridge cni0 10.1.0.1"
        return 1
    fi
    ifconfig $1 $2
}

function show_result() {
    if [ $1 -ne 0 ];then
        echo "TESTSUIT: $2 FAILED"
        return 1
    fi
    echo "TESTSUIT: $2 SUCCESS"
}

function msleep() {
    if [ $# -ne 1 ];then
        echo "use default sleep"
        sleep $@
        return
    fi
    sec=$1
    env | grep GCOV
    if [ $? -eq 0 ];then
        ((sec=$sec+2))
    fi
    sleep $sec
}

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $@" >&2
}

function init_cni_conf()
{
    dtpath="$1"
    mkdir -p /etc/cni/net.d/
    rm -rf /etc/cni/net.d/*
    mkdir -p /opt/cni/bin
    cp $dtpath/bins/isulad-cni /opt/cni/bin
    cp $dtpath/good.conflist /etc/cni/net.d/

    check_valgrind_log
    if [ $? -ne 0 ]; then
        echo "stop isulad failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    start_isulad_with_valgrind --network-plugin cni
    if [ $? -ne 0 ]; then
        echo "start failed"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    return $TC_RET_T
}

function wait_container_state()
{
    while true
    do
        isula inspect -f '{{json .State.Status}}' "$1" | grep "$2"
        if [ $? -eq 0 ];then
            return;
        fi
        sleep 1
    done
}

