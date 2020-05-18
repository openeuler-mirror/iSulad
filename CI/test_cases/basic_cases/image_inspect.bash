#!/bin/bash
#
# attributes: isulad basic image list ps inspect
# concurrent: NA
# spend time: 20

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
##- @Author: WuJing
##- @Create: 2020-05-14
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ${curr_path}/basic_helpers.bash

function test_image_info()
{
  local ret=0
  local image="busybox"
  local test="list && inspect image info test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula pull ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE} 

  isula images | grep busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

  isula inspect -f '{{.image.id}}' ${image} | grep -E '^[0-9a-f]{64}$'
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image id: ${image}" && ((ret++))

  isula inspect -f '{{.image.repo_tags}}' ${image} | grep "${image}:latest"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image repo tags: ${image}" && ((ret++))

  isula inspect -f '{{.image.repo_digests}}' ${image} | grep -E "[\s\D]*${image}@sha256:[0-9a-f]{64}[\s\D]*"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image repo digests: ${image}" && ((ret++))

  isula inspect -f '{{.image.top_layer}}' ${image} | grep -E "^[0-9a-f]{64}$"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image top layer: ${image}" && ((ret++))

  isula inspect -f '{{.image.created}}' ${image} | grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(.[0-9]{2,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image created time: ${image}" && ((ret++))

  isula inspect -f '{{.image.loaded}}' ${image} | grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(.[0-9]{2,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image loaded time: ${image}" && ((ret++))

  [[ $(isula inspect -f '{{.image.size}}' ${image}) -ne 0 ]]
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image size: ${image}" && ((ret++))

  [[ -n $(isula inspect -f '{{.image.Spec.config}}' ${image}) ]]
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image spec config: ${image}" && ((ret++))

  isula inspect -f '{{.image.Spec.config.Cmd}}' ${image} | grep -w "sh"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image cmd config: ${image}" && ((ret++))

  isula rmi ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image ${image}" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_image_info || ((ans++))

show_result ${ans} "${curr_path}/${0}"

