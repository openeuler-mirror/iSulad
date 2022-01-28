#!/bin/bash
#
# attributes: isulad basic container security selinux
# concurrent: NA
# spend time: 15

# Manual Testcase Remarks:
# SELinux is not namespaced, so individual containers cannot have their own separate SELinux policies.
# SELinux will always appear to be “disabled” in a container, though it is running on the host.
# If your application requires SELinux, you cannot use it inside Docker. You will need to use a regular virtual machine.

# Prepare SELinux Environment
# 1. enable selinux on host machine
# 2. set container selinux policy
#  contos/fedora:
#        dnf install container-selinux
#  ubuntu:
#        clone https://github.com/containers/container-selinux.git
#        make install
#        make install-policy
# 3. reference the perpare_selinux_environment function to set selinux context for some dirctory
# 4. restart daemon with --selinux-enabled

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
##- @Author: WuJing
##- @Create: 2020-07-16
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function perpare_selinux_environment()
{
  chcon -R system_u:object_r:container_home_t:s0 /root/.iSulad
  chcon system_u:object_r:container_runtime_exec_t:s0 /usr/bin/isula
  chcon system_u:object_r:container_runtime_exec_t:s0 /usr/local/bin/isula
  chcon system_u:object_r:container_runtime_exec_t:s0 /usr/local/bin/lxc-*
  chcon system_u:object_r:container_unit_file_t:s0 /usr/lib/systemd/system/isulad.service
  chcon -R system_u:object_r:container_var_lib_t:s0 /var/lib/isulad
  chcon -R system_u:object_r:container_log_t:s0 /var/lib/isulad/engines/*/*/*.log
  chcon -R system_u:object_r:container_ro_file_t:s0 /var/lib/isulad/engines/*/*/hostname
  chcon -R system_u:object_r:container_ro_file_t:s0 /var/lib/isulad/engines/*/*/hosts
  if [[ ! -d /var/lib/isulad/storage/overlay ]]; then
    mkdir -p /var/lib/isulad/storage/overlay
  fi
  chcon -R system_u:object_r:container_ro_file_t:s0 /var/lib/isulad/storage/overlay
  if [[ ! -d /var/lib/isulad/storage/overlay2 ]]; then
    mkdir -p /var/lib/isulad/storage/overlay2
  fi
  chcon -R system_u:object_r:container_ro_file_t:s0 /var/lib/isulad/storage/overlay2
  if [[ ! -d /var/lib/isulad/storage/devicemapper ]]; then
    mkdir -p /var/lib/isulad/storage/devicemapper
  fi
  chcon -R system_u:object_r:container_ro_file_t:s0 /var/lib/isulad/storage/devicemapper
  chcon -R system_u:object_r:container_var_run_t:s0 /var/run/isula
  chcon -R system_u:object_r:container_var_run_t:s0 /var/run/isulad 
  chcon system_u:object_r:container_var_run_t:s0 /var/run/isulad.pid 
  chcon system_u:object_r:container_var_run_t:s0 /var/run/isulad.sock
}

function daemon_enable_selinux()
{
  check_valgrind_log
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - memory leak" && return ${FAILURE}

  start_isulad_with_valgrind --selinux-enabled
}

function daemon_disable_selinux()
{
  check_valgrind_log
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - memory leak" && return ${FAILURE}

  start_isulad_with_valgrind
}

function test_isulad_selinux_file_label()
{
  local ret=0
  local image="centos"
  local test="isulad selinux file label test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula pull ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

  isula images | grep ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && return ${FAILURE}

  container=`isula run -itd --security-opt="label=type:container_t" ${image} /bin/bash`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

  mount_label=$(isula inspect -f "{{.MountLabel}}" ${container})
  selinux_context_type=$(echo ${mount_label} | awk -F: '{print $3}')

  cat /etc/selinux/targeted/contexts/lxc_contexts | grep file | grep ${selinux_context_type} 
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid selinux context type: ${image}" && ((ret++))

  isula exec -it ${container} ls -l -Z / | grep dev | grep ${mount_label}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set selinux mount label for root" && ((ret++))

  isula exec -it ${container} ls -l -Z /dev | grep console | grep ${mount_label}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set selinux mount label for /dev/console" && ((ret++))

  isula exec -it ${container} ls -l -Z /dev | grep shm | grep ${mount_label}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set selinux mount label for /dev/shm" && ((ret++))

  isula exec -it ${container} ls -l -Z /dev | grep mqueue | grep ${mount_label}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set selinux mount label for /dev/mqueue" && ((ret++))

  isula exec -it ${container} ls -l -Z /etc/hostname | grep ${mount_label}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set selinux mount label for hostname" && ((ret++))

  isula exec -it ${container} ls -l -Z /etc/hosts | grep ${mount_label}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set selinux mount label for hosts" && ((ret++))

  isula exec -it ${container} ls -l -Z /etc/resolv.conf | grep ${mount_label} 
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set selinux mount label for resolv.conf" && ((ret++))

  isula exec -it ${container} ls -l -Z / | grep proc | grep system_u:object_r:proc_t:s0
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - the selinux context type of proc file system should be proc_t" && ((ret++))

  isula exec -it ${container} ls -l -Z / | grep sys | grep system_u:object_r:sysfs_t:s0
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - the selinux context type of sys file system should be sysfs_t" && ((ret++))

  isula rm -f ${container}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

function test_isulad_selinux_process_label()
{
  local ret=0
  local image="centos"
  local test="isulad selinux process label test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula pull ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

  isula images | grep ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && return ${FAILURE}

  container=`isula run -itd --security-opt="label=type:container_t" ${image} /bin/bash`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

  process_label=$(isula inspect -f "{{.ProcessLabel}}" ${container})
  isula exec -it ${container} ps Z | grep /bin/bash | grep ${process_label}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set selinux process label" && ((ret++))

  isula rm -f ${container}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

function test_isulad_selinux_mount_mode()
{
  local ret=0
  local image="centos"
  local test="isulad selinux mount mode test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula pull ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

  isula images | grep ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

  mkdir -p /tmp/isulad_selinux_share
  container=`isula run -itd --security-opt="label=type:container_t" -v /tmp/isulad_selinux_share:/tmp:z ${image} /bin/bash`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

  mount_label=$(isula inspect -f "{{.MountLabel}}" ${container})

  tmp_file_context=$(stat -c "%C" /tmp/isulad_selinux_share)
  [[ ${tmp_file_context: -2} != "s0" ]] && msg_err "${FUNCNAME[0]}:${LINENO} - /tmp/isulad_selinux_share should be shared mode" && ((ret++))

  isula rm -f ${container}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container" && ((ret++))


  container=`isula run -itd --security-opt="label=type:container_t" -v /tmp/isulad_selinux_share:/tmp:Z ${image} /bin/bash`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

  mount_label=$(isula inspect -f "{{.MountLabel}}" ${container})

  tmp_file_context=$(stat -c "%C" /tmp/isulad_selinux_share)
  [[ ${tmp_file_context} != ${mount_label} ]] && msg_err "${FUNCNAME[0]}:${LINENO} - /tmp/isulad_selinux_share should be exclude mode" && ((ret++))

  isula rm -f ${container}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove container" && ((ret++))

  rm -rf /tmp/isulad_selinux_share

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

daemon_enable_selinux || ((ans++))

perpare_selinux_environment

test_isulad_selinux_file_label || ((ans++))

test_isulad_selinux_process_label || ((ans++))

test_isulad_selinux_mount_mode || ((ans++))

daemon_disable_selinux || ((ans++))

show_result ${ans} "${curr_path}/${0}"
