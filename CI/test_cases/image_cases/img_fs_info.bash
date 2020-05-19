#!/bin/bash
#
# attributes: isulad basic image
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
##- @Author: lifeng
##- @Create: 2020-05-14
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.bash

function test_crictl_image()
{
  local ret=0
  local image="busybox"
  local test="crictl image operation test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  crictl pull ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

  crictl inspecti busybox | grep busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing inspecti image: ${image}" && ((ret++))

  crictl imagefsinfo
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to get image fs info: ${image}" && ((ret++))

  crictl rmi ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image ${image}" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_crictl_image || ((ans++))

show_result ${ans} "${curr_path}/${0}"
