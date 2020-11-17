#!/bin/bash
#
# attributes: isulad volume
# concurrent: YES
# spend time: 25

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
##- @Create: 2020-08-31
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
test="volume mount progagation test => test_volume"
image="busybox"

function cleanup_containers_and_volumes()
{
  isula rm -f `isula ps -a -q`
  isula volume prune -f
}

function test_volume_mount_default()
{
  local ret=0

  mkdir -p /tmp/src

  #run with slave property volume in container
  CONT=$(isula run -v /tmp/src:/tmp/dst -dit --privileged "${image}" /bin/sh)
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container by image $image failed" && ((ret++))

  #check the property from host to container
  mkdir -p /tmp/src_private
  mkdir -p /tmp/src/src_testCE_volume_default
  mount --bind /tmp/src_private /tmp/src/src_testCE_volume_default
  touch /tmp/src_private/src_privatefile
  isula exec -it "$CONT" /bin/sh -c 'ls /tmp/dst/src_testCE_volume_default/src_privatefile || echo -n "host_pass"' > /tmp/host_property_log
  cat /tmp/host_property_log | grep "host_pass"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from host to container ""$CONT"" success ,but expect fail!" && ((ret++))

  #check the property from container to host
  umount /tmp/src/src_testCE_volume_default
  isula exec -it "$CONT" /bin/sh -c 'mkdir /tmp/dst_private;mkdir /tmp/dst/dst_testCE_volume_default;mount --bind /tmp/dst_private /tmp/dst/dst_testCE_volume_default;touch /tmp/dst_private/dst_privatefile'
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec volume in container ""$CONT"" fail!" && ((ret++))
  ls /tmp/src/dst_testCE_volume_default/dst_privatefile
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from container to host success ,but expect fail!" && ((ret++))

  #cleanup
  isula rm -f "$CONT"
  rm -rf /tmp/host_property_log
  umount /tmp/dst
  umount /tmp/src
  rm -rf /tmp/src
  rm -rf /tmp/dst
  rm -rf /tmp/src_private

  return ${ret}
}

function test_volume_mount_private() {

    mkdir -p /tmp/src

    #run with slave property volume in container
    CONT=$(isula run -v /tmp/src:/tmp/dst:private -dit --privileged "${image}" /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container by image $image failed" && ((ret++))

    #check the property from host to container
    mkdir -p /tmp/src_private
    mkdir -p /tmp/src/src_testCE_volume_private
    mount --bind /tmp/src_private /tmp/src/src_testCE_volume_private
    touch /tmp/src_private/src_privatefile
    isula exec -it "$CONT" /bin/sh -c 'ls /tmp/dst/src_testCE_volume_private/src_privatefile || echo -n "host_pass"' > /tmp/host_property_log
    cat /tmp/host_property_log | grep "host_pass"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from host to container ""$CONT"" success ,but expect fail!" && ((ret++))

    #check the property from container to host
    umount /tmp/src/src_testCE_volume_private
    isula exec -it "$CONT" /bin/sh -c 'mkdir /tmp/dst_private;mkdir /tmp/dst/dst_testCE_volume_private;mount --bind /tmp/dst_private /tmp/dst/dst_testCE_volume_private;touch /tmp/dst_private/dst_privatefile'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec volume in container ""$CONT"" fail!" && ((ret++))
    ls /tmp/src/dst_testCE_volume_private/dst_privatefile
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from container to host success ,but expect fail!" && ((ret++))

    #cleanup
    isula rm -f "$CONT"
    rm -rf /tmp/host_property_log
    umount /tmp/dst
    umount /tmp/src
    rm -rf /tmp/src
    rm -rf /tmp/dst
    rm -rf /tmp/src_private
}

function test_volume_mount_rprivate() {

    mkdir -p /tmp/src

    #run with slave property volume in container
    CONT=$(isula run -v /tmp/src:/tmp/dst:rprivate -dit --privileged "${image}" /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container by image $image failed" && ((ret++))

    #check the property from host to container
    mkdir -p /tmp/src_rprivate
    mkdir -p /tmp/src/src_testCE_mount_rprivate
    mount --bind /tmp/src_rprivate /tmp/src/src_testCE_mount_rprivate
    touch /tmp/src_rprivate/src_rprivatefile
    isula exec -it "$CONT" /bin/sh -c 'ls /tmp/dst/src_testCE_mount_rprivate/src_rprivatefile || echo -n "host_pass"' > /tmp/host_property_log
    cat /tmp/host_property_log | grep "host_pass"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from host to container ""$CONT"" success ,but expect fail!" && ((ret++))

    #check the property from container to host
    umount /tmp/src/src_testCE_mount_rprivate
    isula exec -it "$CONT" /bin/sh -c 'mkdir /tmp/dst_rprivate;mkdir /tmp/dst/dst_testCE_mount_rprivate;mount --bind /tmp/dst_rprivate /tmp/dst/dst_testCE_mount_rprivate;touch /tmp/dst_rprivate/dst_rprivatefile'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec volume in container ""$CONT"" fail!" && ((ret++))
    ls /tmp/src/dst_testCE_mount_rprivate/dst_rprivatefile
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from container to host success ,but expect fail!" && ((ret++))

    #cleanup
    rm -rf /tmp/host_property_log
    umount /tmp/dst
    umount /tmp/src
    rm -rf /tmp/src
    rm -rf /tmp/dst
    rm -rf /tmp/src_rprivate
}

function test_volume_mount_rshared() {

    mkdir -p /tmp/src

    #run with slave property volume in container
    CONT=$(isula run -v /tmp/src:/tmp/dst:rshared -dit --privileged "${image}" /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -run container by image $image failed" && ((ret++))

    #check the property from host to container
    mkdir -p /tmp/src_rshared
    mkdir -p /tmp/src/src_testCE_mount_rshared
    mount --bind /tmp/src_rshared /tmp/src/src_testCE_mount_rshared
    touch /tmp/src_rshared/src_rsharedfile
    isula exec -it "$CONT" /bin/sh -c 'ls /tmp/dst/src_testCE_mount_rshared/src_rsharedfile && echo -n "host_pass"' > /tmp/host_property_log
    cat /tmp/host_property_log | grep "host_pass"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from host to container ""$CONT"" fail!" && ((ret++))

    #check the property from container to host
    umount /tmp/src/src_testCE_mount_rshared
    isula exec -it "$CONT" /bin/sh -c 'mkdir /tmp/dst_rshared;mkdir /tmp/dst/dst_testCE_mount_rshared;mount --bind /tmp/dst_rshared /tmp/dst/dst_testCE_mount_rshared;touch /tmp/dst_rshared/dst_rsharedfile'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec volume in container ""$CONT"" fail!" && ((ret++))
    ls /tmp/src/dst_testCE_mount_rshared/dst_rsharedfile
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from container to host fail!" && ((ret++))

    #cleanup
    rm -rf /tmp/host_property_log
    umount /tmp/dst
    umount /tmp/src
    umount /tmp/src/dst_testCE_mount_rshared
    rm -rf /tmp/src
    rm -rf /tmp/dst
    rm -rf /tmp/src_rshared
}

function test_volume_mount_rslave() {

    mkdir -p /tmp/src

    #run with slave property volume in container
    CONT=$(isula run -v /tmp/src:/tmp/dst:rslave -dit --privileged "${image}" /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container by image $image failed" && ((ret++))

    #check the property from host to container
    mkdir -p /tmp/src_rslave
    mkdir -p /tmp/src/src_testCE_mount_rslave
    mount --bind /tmp/src_rslave /tmp/src/src_testCE_mount_rslave
    touch /tmp/src_rslave/src_rslavefile
    isula exec -it "$CONT" /bin/sh -c 'ls /tmp/dst/src_testCE_mount_rslave/src_rslavefile && echo -n "host_pass"' > /tmp/host_property_log
    cat /tmp/host_property_log | grep "host_pass"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from host to container ""$CONT"" fail!" && ((ret++))

    #check the property from container to host
    umount /tmp/src/src_testCE_mount_rslave
    isula exec -it "$CONT" /bin/sh -c 'mkdir /tmp/dst_rslave;mkdir /tmp/dst/dst_testCE_mount_rslave;mount --bind /tmp/dst_rslave /tmp/dst/dst_testCE_mount_rslave;touch /tmp/dst_rslave/dst_rslavefile'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec volume in container ""$CONT"" fail!" && ((ret++))
    ls /tmp/src/dst_testCE_mount_rslave/dst_rslavefile
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from container to host success ,but expect fail!" && ((ret++))

    #cleanup
    rm -rf /tmp/host_property_log
    umount /tmp/dst
    umount /tmp/src
    rm -rf /tmp/src
    rm -rf /tmp/dst
    rm -rf /tmp/src_rslave
}

function test_volume_mount_shared() {

    mkdir -p /tmp/src
    #run with shared property volume in container
    CONT=$(isula run -v /tmp/src:/tmp/dst:shared -dit --privileged "$image" /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container by image $image failed" && ((ret++))

    #check the property from host to container
    mkdir -p /tmp/src_shared
    mkdir -p /tmp/src/src_testCE_v_shared_check
    mount --bind /tmp/src_shared /tmp/src/src_testCE_v_shared_check
    touch /tmp/src_shared/src_sharedfile
    isula exec -it "$CONT" /bin/sh -c 'ls /tmp/dst/src_testCE_v_shared_check/src_sharedfile && echo -n "host_pass"' > /tmp/host_property_log
    cat /tmp/host_property_log | grep "host_pass"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from host to container ""$CONT"" fail!" && ((ret++))

    #check the property from container to host
    umount /tmp/src/src_testCE_v_shared_check
    isula exec -it "$CONT" /bin/sh -c 'mkdir /tmp/dst_shared;mkdir /tmp/dst/dst_testCE_mount_shared_check;mount --bind /tmp/dst_shared /tmp/dst/dst_testCE_mount_shared_check;touch /tmp/dst_shared/dst_sharedfile'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec volume in container ""$CONT"" fail!" && ((ret++))
    ls /tmp/src/dst_testCE_mount_shared_check/dst_sharedfile
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from container to host fail!" && ((ret++))

    #cleanup
    isula rm -f "$CONT"
    rm -rf /tmp/host_property_log
    umount /tmp/dst
    umount /tmp/src
    umount /tmp/src/dst_testCE_mount_shared_check
    rm -rf /tmp/src
    rm -rf /tmp/dst
    rm -rf /tmp/src_shared
}

function test_volume_mount_slave() {

    mkdir -p /tmp/src

    #run with slave property volume in container
    CONT=$(isula run -v /tmp/src:/tmp/dst:slave -dit --privileged "${image}" /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container by image $image failed" && ((ret++))

    #check the property from host to container
    mkdir -p /tmp/src_slave
    mkdir -p /tmp/src/src_testCE_volume_slave
    mount --bind /tmp/src_slave /tmp/src/src_testCE_volume_slave
    touch /tmp/src_slave/src_slavefile
    isula exec -it "$CONT" /bin/sh -c 'ls /tmp/dst/src_testCE_volume_slave/src_slavefile && echo -n "host_pass"' > /tmp/host_property_log
    cat /tmp/host_property_log | grep "host_pass"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from host to container ""$CONT"" fail!" && ((ret++))

    #check the property from container to host
    umount /tmp/src/src_testCE_volume_slave
    isula exec -it "$CONT" /bin/sh -c 'mkdir /tmp/dst_slave;mkdir /tmp/dst/dst_testCE_volume_slave;mount --bind /tmp/dst_slave /tmp/dst/dst_testCE_volume_slave;touch /tmp/dst_slave/dst_slavefile'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - exec volume in container ""$CONT"" fail!" && ((ret++))
    ls /tmp/src/dst_testCE_volume_slave/dst_slavefile
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Property from container to host success ,but expect fail!" && ((ret++))

    #cleanup
    isula rm -f "$CONT"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container ""$CONT"" fail!" && ((ret++))
    rm -rf /tmp/host_property_log
    umount /tmp/dst
    umount /tmp/src
    rm -rf /tmp/src
    rm -rf /tmp/dst
    rm -rf /tmp/src_slave
}

declare -i ans=0

msg_info "${test} starting..."
[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

cleanup_containers_and_volumes
test_volume_mount_default || ((ans++))
cleanup_containers_and_volumes
test_volume_mount_private || ((ans++))
cleanup_containers_and_volumes
test_volume_mount_rprivate || ((ans++))
cleanup_containers_and_volumes
test_volume_mount_rshared || ((ans++))
cleanup_containers_and_volumes
test_volume_mount_rslave || ((ans++))
cleanup_containers_and_volumes
test_volume_mount_shared || ((ans++))
cleanup_containers_and_volumes
test_volume_mount_slave || ((ans++))
cleanup_containers_and_volumes

msg_info "${test} finished with return ${ans}..."

show_result ${ans} "${curr_path}/${0}"
