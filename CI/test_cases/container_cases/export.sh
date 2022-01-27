#!/bin/bash
#
# attributes: isulad basic export container
# concurrent: NA
# spend time: 6

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
##- @Author: wangfengtu
##- @Create: 2020-06-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_image_export()
{
  local ret=0
  local image="busybox"
  local test="export container test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula pull ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

  isula images | grep busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

  CONT=`isula run -itd busybox`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

  isula export -o export.tar ${CONT}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to export ${CONT}" && ((ret++))

  rm -f export.tar

  isula export -o nonexistdir/export.tar ${CONT}
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - export to nonexist directory success" && ((ret++))

  isula rm -f ${CONT}

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_image_export || ((ans++))

show_result ${ans} "${curr_path}/${0}"
