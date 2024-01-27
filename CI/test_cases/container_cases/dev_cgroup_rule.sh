#!/bin/bash
#
# attributes: isulad basic device cgroup rule
# concurrent: NA
# spend time: 5

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
##- @Create: 2020-09-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_cpu_dev_cgoup_rule_spec()
{
    local ret=0
    local runtime=$1
    local image="busybox"
    local test="container device cgroup rule test with (${runtime}) => (${FUNCNAME[@]})"
    local test_dev="/dev/testA"
    local default_config="/etc/default/isulad/config.json"
    local default_config_bak="/etc/default/isulad/config.json.bak"
    local test_cgroup_parent="/testABC"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    rm -f $test_dev
    priv_cid=$(isula run -tid --privileged --runtime $runtime $image /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run priviledged container failed" && ((ret++))
    priv_major_88_cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$priv_cid/config.json | grep "major\": 88" | wc -l)
    priv_minor_88_cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$priv_cid/config.json | grep "minor\": 88" | wc -l)

    mknod $test_dev c 88 88
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mknod failed" && ((ret++))
    isula restart -t 0 $priv_cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - restart priviledge container failed" && ((ret++))
    cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$priv_cid/config.json | grep "major\": 88" | wc -l)
    [[ $? -ne 0 ]]&& [[ $cnt -le $priv_major_88_cnt ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check device major failed" && ((ret++))
    cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$priv_cid/config.json | grep "minor\": 88" | wc -l)
    [[ $? -ne 0 ]] && [[ $cnt -le $priv_minor_88_cnt ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check device minor failed" && ((ret++))
    isula rm -f $priv_cid

    def_cid=$(isula run -tid --runtime $runtime -m 10m $image /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container failed" && ((ret++))
    cp $default_config $default_config_bak
    sed -i '/"linux": {/a \ \t\t"devices": [\n\t\t{\n\t\t\t"type": "c",\n\t\t\t"path": "\/dev\/testA",\n\t\t\t"major": 88,\n\t\t\t"minor": 88\n\t\t}\n\t\t],' $default_config
    stop_isulad_without_valgrind
    start_isulad_with_valgrind --cgroup-parent $test_cgroup_parent
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))
    isula restart -t 0 $def_cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - restart container failed" && ((ret++))
    cat /sys/fs/cgroup/memory/$test_cgroup_parent/$def_cid/memory.limit_in_bytes | grep ^10485760$
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --cgroup-parent cannot work" && ((ret++))
    cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$def_cid/config.json | grep "major\": 88" | wc -l)
    [[ $? -ne 0 ]]&& [[ $cnt -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check device major failed" && ((ret++))
    cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$def_cid/config.json | grep "minor\": 88" | wc -l)
    [[ $? -ne 0 ]] && [[ $cnt -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check device minor failed" && ((ret++))
    isula rm -f $def_cid
    cp $default_config_bak $default_config
    stop_isulad_without_valgrind
    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    cid=$(isula run -tid --device "$test_dev:$test_dev" --runtime $runtime $image /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container failed" && ((ret++))
    cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$cid/config.json | grep "major\": 88" | wc -l)
    [[ $? -ne 0 ]]&& [[ $cnt -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check device major failed" && ((ret++))
    cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$cid/config.json | grep "minor\": 88" | wc -l)
    [[ $? -ne 0 ]] && [[ $cnt -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check device minor failed" && ((ret++))
    isula exec -it $cid sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c 88:88 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c 88:88 rwm: ${image}" && ((ret++))
    isula stop -t 0 $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop container failed" && ((ret++))
    rm -f $test_dev
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - rm device failed" && ((ret++))
    mknod $test_dev c 99 99
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - mknod failed" && ((ret++))
    isula start $cid
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start container failed" && ((ret++))
    cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$cid/config.json | grep "major\": 99" | wc -l)
    [[ $? -ne 0 ]]&& [[ $cnt -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check device major failed" && ((ret++))
    cnt=$(cat ${RUNTIME_ROOT_PATH}/${runtime}/$cid/config.json | grep "minor\": 99" | wc -l)
    [[ $? -ne 0 ]] && [[ $cnt -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - check device minor failed" && ((ret++))
    isula exec -it $cid sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c 99:99 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c 99:99 rwm: ${image}" && ((ret++))
    isula rm -f $cid
    rm -f $test_dev

    isula run -itd --device-cgroup-rule='b *:*' busybox 2>&1 | grep "Invalid value"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid value" && ((ret++))

    isula run -itd --device-cgroup-rule='d *:*' busybox 2>&1 | grep "Invalid value"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid value" && ((ret++))

    isula run -itd --device-cgroup-rule='d *:* xxx' busybox 2>&1 | grep "Invalid value"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Invalid value" && ((ret++))

    c_id=`isula run -itd --device-cgroup-rule='b 11:22 rmw' --device-cgroup-rule='c *:23 rmw' --device-cgroup-rule='c 33:* rm' busybox sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "b 11:22 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check b 11:22 rmw: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c \*:23 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c *:23 rmw: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c 33:\* rm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c 33:* rm: ${image}" && ((ret++))

    isula restart -t 0 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "b 11:22 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check b 11:22 rmw: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c \*:23 rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c *:23 rmw: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "c 33:\* rm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check c 33:* rm: ${image}" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    c_id=`isula run -itd --device-cgroup-rule='a 11:22 rmw' busybox sh`
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "a \*:\* rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check a *:* rwm: ${image}" && ((ret++))

    isula restart -t 0 $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restart container: $c_id" && ((ret++))

    isula exec -it $c_id sh -c "cat /sys/fs/cgroup/devices/devices.list" | grep "a \*:\* rwm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check a *:* rwm: ${image}" && ((ret++))

    isula rm -f $c_id
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container ${c_id}" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return ${ret}
}

declare -i ans=0

for element in ${RUNTIME_LIST[@]};
do
    test_cpu_dev_cgoup_rule_spec $element || ((ans++))
done

show_result ${ans} "${curr_path}/${0}"
