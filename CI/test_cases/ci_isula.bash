#!/bin/bash
#
# This script is the implementation portal for the iSulad project CI.
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
##- @Author: lifeng
##- @Create: 2020-03-30
#######################################################################
declare -a modules

mkdir -p /tmp/coredump
ulimit  -c unlimited
echo "/tmp/coredump/core-%e-%p-%t" > /proc/sys/kernel/core_pattern

function echo_success()
{
    echo -e "\033[1;32m"$@"\033[0m"
}

function echo_failure()
{
    echo -e "\033[1;31m"$@"\033[0m"
}

function usage() {
    echo "Usage: $0 [options]"
    echo "Continuous integration (CI) script for isulad/lcr project"
    echo "Options:"
    echo "    -p, --project       Execute scripts related to the specified project(default=lcr)"
    echo "    -l, --log-dir       Record log of script to specified directory"
    echo "    -h, --help          Script help information"
}

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $@" >&2
}

args=`getopt -o p:l:ah --long project:,log-dir:,help -- "$@"`
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi
eval set -- "$args"

while true; do
    case "$1" in
        -p|--project)       project=$2 ; shift 2 ;;
        -l|--log-dir)       logdir=$2 ; shift 2 ;;
        -h|--help)          usage ; exit 0 ;;
        --)                 shift ; break ;;
        *)                  err "invalid parameter" ; exit -1 ;;
    esac
done

if [ "x${project}" == "x" ];then
    project="lcr"
else
    if [ "${project}" != "lcr" ] && [ "${project}" != "isulad" ];then
        echo "Not supported project ${project}, only [ isulad lcr ] is valid"
        exit 1
    fi
fi

runflag=$(env | grep TESTCASE_RUNFLAG | awk -F '=' '{printf $NF}')
lockfile=$(env | grep TESTCASE_FLOCK | awk -F '=' '{printf $NF}')
scriptslog=$(env | grep TESTCASE_SCRIPTS_LOG | awk -F '=' '{printf $NF}')
contname=$(env | grep TESTCASE_CONTNAME | awk -F '=' '{printf $NF}')

function run_script()
{
    script=$1
    logdir=$2
    runflag=$3

    rm -rf ${script}.pass ${script}.fail
    if [ ! -e ${runflag} ];then
        echo_failure "${script} will not run due to previous error -- SKIP"
        return 0
    fi

    start_time=$(date +%s)
    curdir=`pwd`
    cd ${script%/*}

    if [ "x${logdir}" != "x" ];then
        logfile="${logdir}/${script}.log"
        mkdir -p ${logfile%/*}
        bash -x ${script##*/} > ${logfile} 2>&1
    else
        bash -x ${script##*/}
    fi

    ret=$?
    end_time=$(date +%s)
    dif=$((10#$end_time - 10#$start_time))
    if [ $dif -eq 0 ];then
        dif=1
    fi
    cd ${curdir}
    if [ $ret == 0 ]; then
        echo_success "${script} spend time: ${dif}s -- PASS"
        sed -i "/# spend time:/c # spend time: ${dif}" ${script}
        touch ${script}.pass
    else
        echo_failure "${script} spend time: ${dif}s -- FAIL"
        cat ${logfile}
        touch ${script}.fail
        rm -f $runflag
    fi
}

function run_without_log()
{
    bash -x $1
}
declare -a scripts
testcase_file=$(ls /root | grep testcase_assign_)
suffix=$(echo $testcase_file | awk -F '_' '{print $NF}')
container_property=${suffix:0:1}
while read line
do
    scripts+=(${line})
done < /root/${testcase_file}

function record_log()
{
    flock ${lockfile} printf "[\033[1;35m${contname}\033[0m][\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-90s \033[1;32m%-5s\033[0m\n" ${1} ${2} ${3##*ci_testcases/} "[PASS]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /' >> ${scriptslog}
}

if [[ ${container_property} == 'P' ]]; then
    for script in ${scripts[@]}
    do
        run_script "${script}" "${logdir}" "$runflag" &
    done
    wait
    for script in ${scripts[@]}
    do
        if [[ -e ${script}.fail ]];then
            echo_failure "Run testcases ${script} failed"
            exit 1
        fi
    done
else
    index=0
    total=${#scripts[@]}
    for script in ${scripts[@]}
    do
        index=$(($index+1))
        run_script "${script}" "${logdir}" "$runflag"
        if [[ -e ${script}.fail ]];then
            echo_failure "Run testcases ${script} failed"
            exit 1
        elif [[ ! -e ${runflag} ]];then
            exit 0
        fi
        record_log $index $total $script &
    done
fi

exit 0
