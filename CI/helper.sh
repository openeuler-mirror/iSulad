#!/bin/bash

# all common value and function define here
# all constant values
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
##- @Description: generate cetification
##- @Author: lifeng
##- @Create: 2020-03-30
#######################################################################

time_id=`date "+%s"`
cid=`git rev-parse --short HEAD`

# docker image constant
images_clear_time="5"
image_prefix="lcrd-dev"

# docker container constant
containers_clear_time="5"
container_prefix="isulad_"
CONTAINER_NAME="${container_prefix}${cid}_${time_id}"

tmpdir_prefix="/var/lib/isulad"

testcases_data_dir=/tmp/testcases_data
imgdir=/home/rootfsimg
imgname=$imgdir/disk.img
devname=/dev/loop10
mntdir=/home/mntdir

function remove_deleted_device()
{
    losetup -d `losetup | grep -E "\(deleted\)$" | awk '{print $1}'` 2>/dev/null
}

function listcontainers()
{
    docker ps -a --filter=name="${container_prefix}" --format '{{.Names}}' | awk -F "${container_prefix}" '{print $2}'
}
function remove_container()
{
    docker rm -f "${container_prefix}${1}"
}

function listtmpdirs()
{
    ls $tmpdir_prefix | grep ${container_prefix} | awk -F "${container_prefix}" '{print $2}'
}
function remove_tmpdir()
{
    rm -rf "$tmpdir_prefix/${container_prefix}${1}"
}

function delete_old_resources()
{
    curtime=$1
    maxseconds=`expr $2 \* 3600`
    cur_tag_time=`expr $curtime + 0`

    for tag in `$3`
    do
        tag_time=`echo $tag | awk -F '_' '{print $2}'`
        tag_time=`expr $tag_time + 0`

        delta=`expr $cur_tag_time - $tag_time`
        if [ $delta -gt $maxseconds ];then
            $4 ${tag}
        fi
    done
}
