#!/bin/bash

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: liuyuji
##- @Create: 2021-08-20
#######################################################################

source ../helpers.sh
 
ISULAD_ROOT_PATH="/var/lib/isulad/100000.100000"
LCR_ROOT_PATH="/var/lib/isulad/100000.100000/engines/lcr"
CONTAINER_PATH="/var/lib/isulad/100000.100000/storage/overlay"
IDMAP="100000:100000"
ROOT="0:0"
 
function check_idmap_of_file()
{
   local ret=0
 
   idmap=$(stat -c"%u:%g" ${1})
   [[ "${idmap}" != "${IDMAP}" ]] && msg_err "${2}" && ((ret++))
 
   return ${ret}
}
 
function check_idmap_of_file_in_container()
{
   local ret=0
 
   idmap=$(isula exec -it ${1} stat -c"%u:%g" ${2})
   # delete \r of iamap
   idmap=$(echo ${idmap} | sed -e 's/\r//g')
 
   [[ "${idmap}" != "${ROOT}" ]] && msg_err "${3}" && ((ret++))
 
   return ${ret}
}
 
function start_isulad_with_userns_remap()
{
   local test="start_isulad_with_userns_remap with userns-remap = 100000:100000:65535 => (${FUNCNAME[@]})"
 
   msg_info "${test} starting..."
 
   check_valgrind_log
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - memory leak before current testcase, please check...." && return ${FAILURE}
 
   start_isulad_with_valgrind --userns-remap="100000:100000:65535"
}
 
function check_the_management_directory_for_userns_remap()
{
   local ret=0
   local test="check_the_management_directory_for_userns_remap => (${FUNCNAME[@]})"
 
   msg_info "${test} starting..."
 
   check_idmap_of_file ${ISULAD_ROOT_PATH}/engines "${FUNCNAME[0]}:${LINENO} - The idmap of the storage directory is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   check_idmap_of_file ${ISULAD_ROOT_PATH}/storage "${FUNCNAME[0]}:${LINENO} - The idmap of the storage directory is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
  
   check_idmap_of_file ${ISULAD_ROOT_PATH}/volumes "${FUNCNAME[0]}:${LINENO} - The idmap of the volumes directory is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   mod=$(stat -c"%a" ${ISULAD_ROOT_PATH}/mnt)
   [[ $mod != 751 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - The permissions of the mnt directory are not set correctly" && ((ret++))
 
   mod=$(stat -c"%a" ${ISULAD_ROOT_PATH}/mnt/rootfs)
   [[ $mod != 751 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - The permissions of the rootfs directory are not set correctly" && ((ret++))
 
   msg_info "${test} finished with return ${ret}..."
   return ${ret}
}
 
function test_userns_remap_with_pull_image()
{
   local ret=0
   local image="busybox"
   local test="test_userns_remap_with_pull_image => (${FUNCNAME[@]})"
 
   msg_info "${test} starting..."
 
   isula pull ${image}
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}
 
   isula images | grep busybox
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))
 
   layer_id=$(isula inspect -f '{{.image.top_layer}}' ${image})
 
   check_idmap_of_file ${CONTAINER_PATH}/${layer_id}/diff "${FUNCNAME[0]}:${LINENO} - The idmap of the engines directory is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   check_idmap_of_file ${ISULAD_ROOT_PATH}/storage "${FUNCNAME[0]}:${LINENO} - The idmap of the storage directory is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   for file in ${CONTAINER_PATH}/${layer_id}/diff/*
   do
       check_idmap_of_file ${file} "${FUNCNAME[0]}:${LINENO} - The idmap of the image is not correctly mapped"
       [[ $? != 0 ]] && ((ret++))
   done
  
   msg_info "${test} finished with return ${ret}..."
   return ${ret}
}
 
function test_userns_remap_with_create_container()
{
   local ret=0
   local image="busybox"
   local test="test_userns_remap_with_create_container => (${FUNCNAME[@]})"
 
   msg_info "${test} starting..."
 
   CID=$(isula create -it busybox)
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to create container" && ((ret++))
 
   check_idmap_of_file ${CONTAINER_PATH}/${CID}/diff "${FUNCNAME[0]}:${LINENO} - The idmap of the diff directory is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   check_idmap_of_file ${CONTAINER_PATH}/${CID}/merged "${FUNCNAME[0]}:${LINENO} - The idmap of the merged directory is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
  
   check_idmap_of_file ${CONTAINER_PATH}/${CID}/work "${FUNCNAME[0]}:${LINENO} - The idmap of the work directory is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   check_idmap_of_file ${LCR_ROOT_PATH}/${CID}/hostname "${FUNCNAME[0]}:${LINENO} - The idmap of the hostname is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   check_idmap_of_file ${LCR_ROOT_PATH}/${CID}/hosts "${FUNCNAME[0]}:${LINENO} - The idmap of the hosts is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   check_idmap_of_file ${LCR_ROOT_PATH}/${CID}/mounts "${FUNCNAME[0]}:${LINENO} - The idmap of the mounts is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   check_idmap_of_file ${LCR_ROOT_PATH}/${CID}/resolv.conf "${FUNCNAME[0]}:${LINENO} - The idmap of the resolv.conf is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   isula start ${CID}
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to start container" && ((ret++))
   testcontainer ${CID} running
 
   isula rm -f ${CID}
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to rm container" && ((ret++))
 
   msg_info "${test} finished with return ${ret}..."
   return ${ret}
}
 
function check_lcr_config()
{
   local ret=0
   local image="busybox"
   local test="check_lcr_config  => (${FUNCNAME[@]})"
  
   msg_info "${test} starting..."
   CID=`isula run -itd ${image}`
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to create container" && ((ret++))  
   testcontainer ${CID} running
  
   cat "${LCR_ROOT_PATH}/${CID}/config"  | grep "lxc.idmap = u 0 100000 65535"
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to find uidmap in lcr config" && ((ret++)) 
  
   cat "${LCR_ROOT_PATH}/${CID}/config"  | grep "lxc.idmap = g 0 100000 65535"
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to find gidmap in lcr config" && ((ret++)) 
  
   isula rm -f ${CID}
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to rm container" && ((ret++))  
  
   return ${ret}
}
 
function test_userns_remap_with_create_file_in_container()
{
   local ret=0
   local image="busybox"
   local test="test_userns_remap_with_create_file_in_container  => (${FUNCNAME[@]})"
   local filename="test"
 
   msg_info "${test} starting..."
  
   CID=$(isula run -itd ${image})
   isula exec -it ${CID} touch ${filename}
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to create file in container" && ((ret++))
 
   check_idmap_of_file_in_container ${CID} ${filename} "${FUNCNAME[0]}:${LINENO} - The idmap is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   check_idmap_of_file ${CONTAINER_PATH}/${CID}/diff/${filename} "${FUNCNAME[0]}:${LINENO} - The idmap is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))
 
   isula rm -f $CID
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to rm container" && ((ret++))  
 
   msg_info "${test} finished with return ${ret}..."
   return ${ret}  
}

test_cancel_userns_remap()
{
   local ret=0
   local image="busybox"
   local test="tess_cancel_userns_remap  => (${FUNCNAME[@]})"
   local filename="test"
 
   msg_info "${test} starting..."
  
   CID=$(isula run -itd --userns=host ${image})
   isula exec -it ${CID} touch ${filename}
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to create file in container" && ((ret++))
 
   check_idmap_of_file_in_container ${CID} ${filename} "${FUNCNAME[0]}:${LINENO} - The idmap is not correctly mapped"
   [[ $? != 0 ]] && ((ret++))

   idmap=$(stat -c"%u:%g" ${CONTAINER_PATH}/${CID}/diff/${filename})
   [[ "${idmap}" != "${ROOT}" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - The idmap is not correctly mapped" && ((ret++))
   
   cat "${LCR_ROOT_PATH}/${CID}/config"  | grep "lxc.idmap = u 0 100000 65535"
   [[ $? == 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Uidmap should not exist in lcr config" && ((ret++)) 
  
   cat "${LCR_ROOT_PATH}/${CID}/config"  | grep "lxc.idmap = g 0 100000 65535"
   [[ $? == 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Gidmap should not exist in lcr config" && ((ret++)) 
   
   isula rm -f $CID
   [[ $? != 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - Failed to rm container" && ((ret++))  
 
   msg_info "${test} finished with return ${ret}..."
   return ${ret}  
}

declare -i ans=0
 
start_isulad_with_userns_remap || ((ans++))
check_the_management_directory_for_userns_remap || ((ans++))
test_userns_remap_with_pull_image || ((ans++))
test_userns_remap_with_create_container || ((ans++))
check_lcr_config || ((ans++))
test_userns_remap_with_create_file_in_container || ((ans++))
test_cancel_userns_remap || ((ans++))
 
check_valgrind_log
start_isulad_without_valgrind

show_result ${ans} "user namespaces remap"
