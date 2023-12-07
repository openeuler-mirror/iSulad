#!/bin/bash
#
# attributes: isulad basic container hook
# concurrent: NA
# spend time: 7

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
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
##- @Create: 2020-06-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

test_data_path=$(realpath $curr_path/test_data)

# $1 hook process 
# $2 container id
# $3 expect container status
# $4 process statement
function test_kill_hook()
{
    for a in `seq 20`
    do
        bpid=`ps aux | grep "$1" | grep -v grep | awk '{print $2}'`
        if [ "x" != "x$bpid" ];then
            kill -9 $bpid
            break
        else
            sleep .5
            continue
        fi
    done

    if [ "x" != "x$4" ];then
        for a in `seq 20`
        do
            bpid=`ps aux | grep "$4" | grep -v grep | awk '{print $2}'`
            if [ "x" != "x$bpid" ];then
                kill -9 $bpid
                break
            else
                sleep .5
                continue
            fi
        done
    fi

    status=`isula inspect -f '{{json .State.Status}}' $2`
    if [ "$status" == "$3" ];then
        echo "get right status"
        return 0
    else
        echo "expect $2 $3, but get $status"
        return 1
    fi
}

function test_hook_ignore_poststart_error_spec()
{
    local ret=0
    local image="busybox"
    local runtime=$1
    local test="container hook test => (${FUNCNAME[@]}) => $runtime"
    CONT=test_hook_spec
    cp ${test_data_path}/poststart.sh /tmp/

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    isula run -n $CONT -itd --runtime $runtime --hook-spec ${test_data_path}/oci_hook_poststart_check.json ${image} &
    
    # when runc container run poststart hook, the process structure is different from lxc
    if [ $runtime == "lcr" ]; then
        test_kill_hook "poststart.sh" $CONT \"running\"
    else
        test_kill_hook "poststart.sh" $CONT \"exited\" "sleep 300"
    fi
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to test kill hook: ${image}" && ((ret++))
    
    isula stop -t 0 ${CONT}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to stop ${CONT}" && ((ret++))

    isula rm ${CONT}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm ${CONT}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

for element in ${RUNTIME_LIST[@]};
do
    test_hook_ignore_poststart_error_spec $element || ((ans++))
done

show_result ${ans} "${curr_path}/${0}"
