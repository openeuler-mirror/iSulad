#!/bin/bash
#
# attributes: isulad basic image with digest
# concurrent: NA
# spend time: 4

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
##- @Author: zhongtao
##- @Create: 2023-06-02
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_image_with_digest()
{
  local ret=0
  local image="busybox"
  local image_digest="busybox@sha256:5cd3db04b8be5773388576a83177aff4f40a03457a63855f4b9cbe30542b9a43"
  local test="pull && inspect && tag image with digest test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula pull ${image_digest}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}
  
  isula tag ${image_digest} ${image}:latest
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to tag image: ${image}" && return ${FAILURE}

  isula images | grep busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

  isula inspect -f '{{.image.id}}' ${image} | grep -E '^[0-9a-f]{64}$'
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image id: ${image}" && ((ret++))

  isula inspect -f '{{.image.repo_digests}}' ${image} | grep -E "[\s\D]*${image}@sha256:[0-9a-f]{64}[\s\D]*"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image repo digests: ${image}" && ((ret++))

  isula inspect -f '{{.image.repo_tags}}' ${image_digest} | grep "${image}:latest"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image digest: ${image_digest}" && ((ret++))

  isula run -tid --name test ${image_digest} sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image digest: ${image_digest}" && ((ret++))

  isula rm -f test
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container" && ((ret++))
  
  isula run -tid --name test ${image} sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image tag: ${image}:latest" && ((ret++))

  isula rm -f test
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container" && ((ret++))

  isula inspect -f '{{.image.repo_tags}}' ${image} | grep "${image}:latest"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid image repo tags: ${image}" && ((ret++))

  isula rmi ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image ${image}" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_image_with_digest || ((ans++))

show_result ${ans} "${curr_path}/${0}"

