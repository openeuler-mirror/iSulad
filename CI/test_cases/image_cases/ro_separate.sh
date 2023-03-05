#!/bin/bash
#
# attributes: isulad basic image
# concurrent: NA
# spend time: 22

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: wangrunze
##- @Create: 2023-03-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
single_image="${curr_path}/busybox.tar"

function test_separate_ro()
{
  local ret=0
  local test="isula separate ro test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  sed -i 's/"storage-enable-remote-layer": false/"storage-enable-remote-layer": true/' /etc/isulad/daemon.json
  start_isulad_with_valgrind
  wait_isulad_running

  isula rmi busybox

  isula pull busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - pull image failed" && ((ret++))

  isula run -tid --name test_separate busybox /bin/sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container failed" && ((ret++))

  isula stop test_separate
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop container failed" && ((ret++))

  isula rmi busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - remove image failed" && ((ret++))

  isula load -i $single_image
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load image failed: ${rootfs_tar}" && ((ret++))

  check_valgrind_log
  [[ $? -ne 0 ]] && msg_err "separate ro test - memory leak, please check...." && ((ret++))

  sed -i 's/"storage-enable-remote-layer": true/"storage-enable-remote-layer": false/' /etc/isulad/daemon.json
  start_isulad_with_valgrind
  wait_isulad_running

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_separate_ro || ((ans++))

show_result ${ans} "${curr_path}/${0}"
