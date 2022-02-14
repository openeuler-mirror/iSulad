#!/bin/bash
#
# attributes: isulad basic container hook
# concurrent: NA
# spend time: 1

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
##- @Description: devicemapper storage-opts test
##- @Author: gaohuatao
##- @Create: 2020-06-03
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh
image_busybox="busybox"

function do_pre()
{
    local ret=0

    isula rm -f `isula ps -qa`
    isula rmi `isula images | awk 'NR>1{print $3}'`

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    cp -f /etc/isulad/daemon.json /etc/isulad/daemon.bak
    sed -i '/dm.basesize/d' /etc/isulad/daemon.json
    sed -i '/    \"dm\.fs\=ext4\"\,/{n;d}' /etc/isulad/daemon.json
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to modify daemon.json" && ((ret++))
    sed -i '/    \"dm\.fs\=ext4\"\,/a\    \"dm\.min\_free\_space\=10\%\"\,\n    \"dm\.mkfsarg\=\-b 1024\"\,\n    \"dm\.mkfsarg=\-I 128\"\,\n    \"dm\.mountopt\=discard\"' /etc/isulad/daemon.json
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to modify daemon.json" && ((ret++))

    reinstall_thinpool
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to reconfig isulad-thinpool" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    return $ret
}

function do_test()
{
    local ret=0

    local test="devicemapper dm.mkfsarg and dm.mountopt params test => (${FUNCNAME[@]})"
    msg_info "${test} starting..."

    isula pull $image_busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image_busybox}" && ((ret++))
    
    id=`isula run -tid $image_busybox`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container failed" && ((ret++))

    dm=`ls /dev/mapper/ | grep $id`
    block_size=`tune2fs -l /dev/mapper/$dm | grep 'Block size' | awk '{print $3}'`
    [[ $block_size -ne 1024 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get dm block size:${block_size} value not as expected value:1024" && ((ret++))

    inode_size=`tune2fs -l /dev/mapper/$dm | grep 'Inode size' | awk '{print $3}'`
    [[ $inode_size -ne 128 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get dm inode size:${inode_size} value not as expected value:128" && ((ret++))

    mnt_opt=`mount | grep $id | grep discard`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - get container mount discard failed" && ((ret++))

    isula rm -f $id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm container id:$id failed" && ((ret++))

    isula rmi $image_busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rmi image:$image_busybox failed" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

function do_post()
{
    local ret=0

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to recover daemon.json" && ((ret++))

    reinstall_thinpool
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to reconfig isulad-thinpool" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    return ${ret}
}

declare -i ans=0

driver_name=$(isula info | grep "Storage Driver" | cut -d " " -f3)
if [[ "x$driver_name" == "xdevicemapper" ]]; then
    do_pre || ((ans++))
    do_test || ((ans++))
    do_post || ((ans++))
fi

show_result ${ans} "${curr_path}/${0}"
