#!/bin/sh
#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2019. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description: isulad check
##- @Author: maoweiyong
##- @Create: 2019-02-25
#######################################################################*/

source /etc/sysconfig/iSulad

#健康检查文件
healthcheck_file="/var/run/isulad/isulad_healcheck_status"
createfile_time="/var/run/isulad/isulad_healcheck_ctime"

#健康检查超时时间
declare -i timeout_time=900
declare -i status_change_time=930

#status_check
#只进行基本的daemon状态检测，包括pid是否存在，进程状态是否异常，不进行其他的检查
#正常返回0，异常返回1
function status_check() {
    pid=$1
    if [ $? -ne 0 ];then
        echo "cat /var/run/isulad.pid failed!"
        return 1
    fi

    cat /proc/${pid}/status >> /dev/null 2>&1
    if [ $? -ne 0 ];then
        echo "/var/run/isulad.pid exitst while process not exists!"
        return 1
    fi

    dstate=`cat /proc/${pid}/status | grep State | awk '{print $2}'`
    if [[ ("${dstate}x" == "Zx") || ("${dstate}x" == "Tx") ]]; then
        # Z状态、T状态
        echo " dstate="${dstate}", should restart!"
        return 1
    fi
    return 0
}
#轮询三次进行status_check
#如果三次都失败，则失败，如果有一次超时6s，也失败
#如果三次有一次成功，则成功
function basic_check()
{
    for((i=1;i<=5;i++));
    do
        sleep 2
        date_start=$(date +%s)

        tmp_id=`cat /var/run/isulad.pid`
        status_check $tmp_id
        check_daemon=$?

        date_end=$(date +%s)
        if [ ${check_daemon} -eq 0 ];then
            return 0
        elif [ $((date_end-date_start)) -gt 6 ];then
            echo "check date is more than 6s!"
            return 1
        fi
    done
    return 1
}

#获取健康检查状态文件的创建时间
#如果文件running超过status_change_time，则代表健康检查进程故障，或者检查本身故障，或者状态文件被人恶意损坏或者更改
#此时需要重新进行健康检查并删除原文件
function createtime_check() {
    if [ ! -f "${createfile_time}" ];then
        return 1
    fi
    date_create=$(cat ${createfile_time})
    date_now=$(date +%s)
    if [ $((date_now-date_create)) -gt ${status_change_time} ]; then
        return 1
    fi
    return 0
}

function clean_healthcheck() {
    rm -rf ${healthcheck_file}
    rm -rf ${createfile_time}
}

#执行健康检查的后台线程，需要维护健康检查运行时
function health_check() {
    create_time=$(date +%s)

    touch ${createfile_time}
    chmod 0640 ${createfile_time}
    touch ${healthcheck_file}
    chmod 0640 ${healthcheck_file}

    echo ${create_time} > ${createfile_time}
    echo "running" > ${healthcheck_file}

    i=0
    ret=0

    while [ $i -lt ${timeout_time} ]
    do
        timeout -s 9 1 isula version $SYSMONITOR_OPTIONS
        ret=$?
        if [ $ret -eq 0 ];then
            echo "success">${healthcheck_file}
            return
        else
            if [ $ret -ne 137 ];then
                sleep 1
            fi
            i=$(($i+1))
        fi
    done
    echo "failed">${healthcheck_file}
    return
}

#1、首先进行基本检查，最多耗时6s，如果错误，则直接返回错误；如果成功，则返回成功
basic_check
if [ $? -ne 0 ];then
    echo "basic check failed!"
    exit 1
fi

#2、基本检查通过后，才需要进行健康检查状态的判断
#如果健康状态文件不存在，则进行健康检查，直接返回
if [ ! -f ${healthcheck_file} ];then
    health_check &
    exit 0
fi

#3、如果文件存在，则代表进行过检查，根据检查结果，做相应处理
file_status=$(cat ${healthcheck_file} 2>/dev/null)
createtime_check
file_change_time=$?
case "$file_status" in
        #上次的检查还在运行且没有超时
    running)
        #或者超过规定时间还是running，代表进程可能异常或者状态位被恶意篡改，都需要重新拉起进程检查脚本
        #但是此时不代表服务已经异常，所以不重启服务
        if [ ${file_change_time} -ne 0 ];then
            clean_healthcheck
            health_check &
        fi
        exit 0
        ;;
        #如果上次检查已经成功了，则直接重新拉新的进程并返回成功
    success)
        clean_healthcheck
        health_check &
        exit 0
        ;;
        #其他情况，可能是失败了，需要重新由sysmonitor restart服务
    *)
        clean_healthcheck
        exit 1
        ;;
esac
exit 0
