#!/bin/bash
#
# attributes: isulad basic remove image
# concurrent: NA
# spend time: 8

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
##- @Create: 2020-05-14
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.bash

function test_image_remove()
{
  local ret=0
  local image="busybox"
  local test="remove image test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula pull ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

  isula images | grep busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

  CONT=`isula run -itd busybox`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

  local image_remove_log=/tmp/image_remove.log
  isula rmi ${image} > ${image_remove_log} 2>&1
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check image ${image} used by container" && ((ret++))

  cat ${image_remove_log} | grep "Error response from daemon: Image used by" | grep "${CONT}"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check image ${image} used by container error info" && ((ret++))

  isula rm -f ${CONT}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove ${CONT}" && ((ret++))

  isula rmi ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rmi image ${image}" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_image_remove || ((ans++))

show_result ${ans} "${curr_path}/${0}"
