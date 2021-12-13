#!/bin/bash
#
# attributes: isulad basic image
# concurrent: NA
# spend time: 6

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
source ../helpers.sh

function test_image_list()
{
  local ret=0
  local image="hello-world"
  local image_busybox="busybox"
  local INVALID_IMAGE="k~k"
  local test="list images info test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula pull ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

  isula pull $INVALID_IMAGE
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - sueccess to pull image: ${INVALID_IMAGE}, expect fail" && return ${FAILURE}

  isula images | grep hello
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

  isula pull ${image_busybox}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image_busybox}" && return ${FAILURE}

  isula images | grep busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

  count=`isula images --filter "reference=*hello*" | grep hello | wc -l`
  [[ $count -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image} with filter" && ((ret++))

  isula images --filter "since=${image}"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to list images with since: ${image}" && ((ret++))

  isula images --filter "before=${image}"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to list images with before: ${image}" && ((ret++))

  isula images --filter "since=${image_busybox}"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to list images with since: ${image_busybox}" && ((ret++))

  isula images --filter "before=${image_busybox}"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to list images with since: ${image_busybox}" && ((ret++))

  isula rmi ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image ${image}" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_image_list || ((ans++))

show_result ${ans} "${curr_path}/${0}"
