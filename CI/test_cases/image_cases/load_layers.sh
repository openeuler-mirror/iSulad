#!/bin/bash
#
# attributes: isulad basic load layers
# concurrent: NA
# spend time: 5

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
##- @Author: zhangxiaoyu
##- @Create: 2023-05-30
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_load_layers()
{
  local ret=0
  local image="busybox"
  local test="load layers test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula pull ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

  isula images | grep busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

  CONT=$(isula run -itd busybox)
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

  local json_file=/var/lib/isulad/storage/overlay-layers/${CONT}/layer.json
  test -f ${json_file}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - layer json not exist" && ((ret++))

  check_valgrind_log
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

  sed -i '2i \"incompelte\"\: true\,' ${json_file}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to modify layer json" && ((ret++))

  start_isulad_with_valgrind
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

  test -f ${json_file}
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - layer json not exist" && ((ret++))

  isula rm -f ${CONT}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove ${CONT}" && ((ret++))

  isula rmi ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rmi image ${image}" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_load_layers || ((ans++))

show_result ${ans} "${curr_path}/${0}"
