#!/bin/bash
#
# attributes: isulad volume
# concurrent: YES
# spend time: 15

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
##- @Author: wangfengtu
##- @Create: 2020-08-31
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
test="volume test => test_volume"

function cleanup_containers_and_volumes() {
    isula rm -f $(isula ps -a -q)
    isula volume prune -f
}

function test_volume_help() {
    local ret=0

    isula --help | grep volume
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula --help failed" && ((ret++))

    isula volume --help | grep "isula volume"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula volume --help failed" && ((ret++))

    isula volume rm --help | grep "isula volume rm"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula volume rm --help failed" && ((ret++))

    isula volume nonexist
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula volume noexist should failed" && ((ret++))

    return "${ret}"
}

function test_volume_ls() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -tid busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container without volume" && ((ret++))

    isula run -tid -v vol:/vol:ro busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with volume" && ((ret++))

    n=$(isula volume ls | wc -l)
    [[ $n -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to list volume" && ((ret++))

    return "${ret}"
}

# test prune can remove all volumes unused
function test_volume_prune_remove() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -tid --name vol --mount src=vol,dst=/vol,readonly=true busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with volume" && ((ret++))

    isula rm -f vol
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container with volume" && ((ret++))

    echo y | isula volume prune
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to prune volumes" && ((ret++))

    n=$(isula volume ls | wc -l)
    [[ $n -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - volume not all removed after prune" && ((ret++))

    return "${ret}"
}

# test prune can not remove used volume
function test_volume_prune_cannot_remove() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -ti --name vol -v vol:/vol:z vol echo vol
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with volume failed" && ((ret++))

    isula volume prune -f
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to prune volumes" && ((ret++))

    n=$(isula volume ls -q | wc -l)
    [[ $n -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - volume number not right after prune" && ((ret++))

    return "${ret}"
}

# test --rm can remove anonymous volume but not non-anonymous
function test_volume_auto_rm() {
    local ret=0

    cleanup_containers_and_volumes

    isula run --rm -ti --name autorm -v vol:/vol vol echo vol
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with non-anonymous failed" && ((ret++))

    isula inspect autorm
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - container still exist after container stopped" && ((ret++))

    n=$(isula volume ls -q | wc -l)
    [[ $n -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - volume still exist after container stopped" && ((ret++))

    return "${ret}"
}

function test_volume_rm() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -ti --name vol -v vol:/vol vol echo vol
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with non-anonymous failed" && ((ret++))

    isula rm -f vol
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container with volume" && ((ret++))

    isula volume rm vol
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove specified volume" && ((ret++))

    return "${ret}"
}

function test_volume_volumes_from() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -tid --name vol1 -v volumes_from:/volumes_from --mount type=bind,source=/home,target=/vol3,bind-selinux-opts=z,bind-propagation=rprivate vol sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container for volumes-from failed" && ((ret++))

    isula run -tid --name vol2 --volumes-from vol1 busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with --volumes-from failed" && ((ret++))

    isula exec -ti vol2 stat /vol/dir/dir
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from anonymous volume failed" && ((ret++))

    isula exec -ti vol2 stat /volumes_from
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from named volume failed" && ((ret++))

    isula run -tid --name vol3 --volumes-from vol1:ro busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with --volumes-from readonly failed" && ((ret++))

    isula exec -ti vol3 touch /volumes_from/fail
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from readonly failed" && ((ret++))

    isula run -tid --name vol4 --volumes-from vol3 busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with --volumes-from readonly failed" && ((ret++))

    isula exec -ti vol4 touch /volumes_from/fail
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from default readonly failed" && ((ret++))

    isula run -tid --name vol5 --volumes-from vol3:rw busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with --volumes-from readonly failed" && ((ret++))

    isula exec -ti vol5 touch /volumes_from/fail
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from readwrite failed" && ((ret++))

    return "${ret}"
}

function test_volume_anonymous() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -tid --name vol vol sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run image with volume" && ((ret++))

    isula exec -ti vol stat /vol
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - vol1 not found" && ((ret++))

    isula exec -ti vol stat /vol2
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - vol2 not found" && ((ret++))

    return "${ret}"
}

function test_volume_volume() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -tid --name vol1 -v /vol1 busybox touch /vol1/test
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run first container" && ((ret++))

    isula run -tid --name vol2 -v vol2:/vol2 busybox touch /vol2/test
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run second container" && ((ret++))

    return "${ret}"
}

function test_volume_mount() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -tid --name vol1 --mount dst=/vol1 busybox touch /vol1/test
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run first container" && ((ret++))

    isula run -tid --name vol2 --mount src=vol2,dst=/vol2,ro=false busybox touch /vol2/test
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run second container" && ((ret++))

    isula run -tid --name vol3 --mount type=bind,source=/home,target=/vol3,bind-selinux-opts=z,bind-propagation=rprivate busybox touch /vol3/test
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run third container" && ((ret++))

    return "${ret}"
}

function test_volume_restore() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -tid --name restore -v vol_restore:/vol busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container for restore volume" && ((ret++))

    isula exec -ti restore touch /vol/restore.txt
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create file for restore volume" && ((ret++))

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    isula exec -ti restore cat /vol/restore.txt
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restore volume" && ((ret++))

    return "${ret}"
}

function test_volume_reuse() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -tid -v reuse:/vol vol touch /vol/reuse.txt
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container for volume reuse failed" && ((ret++))

    isula run -ti -v reuse:/vol vol cat /vol/reuse.txt
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - reuse container volume failed" && ((ret++))

    return "${ret}"
}

function test_volume_copy() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -ti --rm --mount target=/usr vol stat /usr/sbin
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test default copy failed" && ((ret++))

    isula run -tid --name vol -ti vol sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run vol failed" && ((ret++))

    isula exec -ti vol cat /vol/hello | grep world
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy regular failed" && ((ret++))

    isula exec -ti vol stat /vol/link | grep "Links: 2"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy hard link failed" && ((ret++))

    isula exec -ti vol readlink /vol/softlink | grep hello
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy soft link failed" && ((ret++))

    isula exec -ti vol stat /vol/dev | grep "character special file"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy char device failed" && ((ret++))

    isula exec -ti vol stat /vol/dir/dir
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy recursive failed" && ((ret++))

    isula run -ti --rm --mount target=/usr,volume-nocopy=true vol echo hello
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - nocopy parameter of --mount start container failed" && ((ret++))

    isula run -ti --rm --mount target=/usr,volume-nocopy=true,bind-selinux-opts=z vol stat /usr/sbin
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - nocopy parameter of --mount take no effect" && ((ret++))

    isula run -ti --rm -v test:/usr:nocopy vol echo hello
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - nocopy parameter of -v start container failed" && ((ret++))

    isula run -ti --rm -v test:/usr:nocopy vol stat /usr/sbin
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - nocopy parameter of -v take no effect" && ((ret++))

    return "${ret}"
}

function test_volume_conflict() {
    local ret=0

    cleanup_containers_and_volumes

    isula run -tid --name vol -v vol3:/vol vol sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with conflict destination should fail condition 1" && ((ret++))

    nums=$(isula inspect -f "{{.Mounts}}" vol | grep _data | wc -l)
    [[ $nums -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run image with volume" && ((ret++))

    isula inspect -f "{{.Mounts}}" vol | grep vol3
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run image with volume" && ((ret++))

    isula rm -f vol
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container" && ((ret++))

    isula run -tid -v /vol --mount type=volume,destination=/vol busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with conflict destination should fail condition 2" && ((ret++))

    isula run -tid -v vol5:/vol5 -v /home:/vol5 busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with conflict destination should fail condition 3" && ((ret++))

    return "${ret}"
}

function test_volume_invalid_modes() {
    local ret=0

    cleanup_containers_and_volumes

    # test invalid modes
    isula run -tid --rm -v aaa:/aaa:rslave busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container -v with volume and propagation should fail" && ((ret++))

    isula run -tid --rm -v /home:/aaa:nocopy busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container -v with bind and nocopy should fail" && ((ret++))

    isula run -tid --rm --mount src=aaa,dst=/aaa,bind-propagation=rslave busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container --mount with volume and propagation should fail" && ((ret++))

    isula run -tid --rm --mount src=/home,dst=/aaa:nocopy busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container --mount with bind and nocopy should fail" && ((ret++))

    return "${ret}"
}

function test_volume_init_fail() {
    local ret=0

    cleanup_containers_and_volumes

    check_valgrind_log
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

    rm -rf /var/lib/isulad/volumes
    touch /var/lib/isulad/volumes

    start_isulad_with_valgrind
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad should fail" && ((ret++))

    rm -f /var/lib/isulad/volumes

    start_isulad_with_valgrind
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

    return "${ret}"
}

function test_volume_container_rmv() {

    local ret=0

    cleanup_containers_and_volumes

    # test container remove with argument -v
    isula run -tid -n volume_rmv -v aaa:/aaa -v /bbb busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container fail" && ((ret++))

    isula rm -f -v volume_rmv
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - remove container with --volume fail" && ((ret++))

    n=$(isula volume ls | wc -l)
    [[ $n -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to list volume" && ((ret++))

    return "${ret}"
}

function test_volume_tmpfs_basic() {
    local ret=0

    cleanup_containers_and_volumes

    # test tmpfs basic
    isula run -tid -n tmpfs --mount type=tmpfs,dst=/tmpfs,tmpfs-size=1m,tmpfs-mode=1700 --tmpfs /tmpfs2 busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run tmpfs container fail" && ((ret++))

    isula exec -ti tmpfs stat /tmpfs | grep "1700/drwx"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - /tmpfs mode not right" && ((ret++))

    isula exec -ti tmpfs stat /tmpfs2 | grep "1777/drwx"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - /tmpfs2 mode not right" && ((ret++))

    isula exec -ti tmpfs dd if=/dev/zero of=/tmpfs/data bs=1k count=2000
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - dd should fail" && ((ret++))

    isula exec -ti tmpfs stat /tmpfs/data | grep "Size: 1048576"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - /tmpfs/data size not right" && ((ret++))

    return "${ret}"
}

function test_volume_tmpfs_invalid() {
    local ret=0

    cleanup_containers_and_volumes

    # test tmpfs basic
    isula run -tid -n tmpfs --mount type=tmpfs,dst=/tmpfs --mount type=bind,src=/home,dst=/tmpfs busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - conflict mount point should fail" && ((ret++))

    isula run -tid -n tmpfs --mount type=tmpfs,dst=/tmpfs,tmpfs-size=-1 busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid tmpfs size should fail" && ((ret++))

    isula run -tid -n tmpfs --mount type=tmpfs,dst=/tmpfs,tmpfs-mode=-1 busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid tmpfs mode should fail" && ((ret++))

    isula run -tid -n tmpfs --mount type=tmpfs,dst=/tmpfs,volume-nocopy=true busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - should fail if use volume nocopy" && ((ret++))

    return "${ret}"
}

function prepare_test_volume() {
    local ret=0

    isula load -i test_data/vol.tar
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load volume image failed" && ((ret++))

    return "${ret}"
}

function post_test_volume() {
    cleanup_containers_and_volumes
    isula rmi vol
}

declare -i ans=0

msg_info "${test} starting..."
[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

prepare_test_volume || ((ans++))

test_volume_help || ((ans++))
test_volume_init_fail || ((ans++))
test_volume_ls || ((ans++))
test_volume_prune_remove || ((ans++))
test_volume_prune_cannot_remove || ((ans++))
test_volume_auto_rm || ((ans++))
test_volume_rm || ((ans++))
test_volume_volumes_from || ((ans++))
test_volume_anonymous || ((ans++))
test_volume_volume || ((ans++))
test_volume_mount || ((ans++))
test_volume_restore || ((ans++))
test_volume_reuse || ((ans++))
test_volume_copy || ((ans++))
test_volume_conflict || ((ans++))
test_volume_invalid_modes || ((ans++))
test_volume_container_rmv || ((ans++))
test_volume_tmpfs_basic || ((ans++))
test_volume_tmpfs_invalid || ((ans++))

post_test_volume

msg_info "${test} finished with return ${ans}..."

show_result "${ans}" "${curr_path}/${0}"
