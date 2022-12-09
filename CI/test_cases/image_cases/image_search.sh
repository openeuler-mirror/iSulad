#!/bin/bash
#
# attributes: isulad basic image search
# concurrent: NA
# spend time: 4

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
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
##- @Create: 2022-11-25
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_image_search()
{
  local ret=0
  local image="busybox"
  local invalid_image="https://isula.io/busybox"
  local test="search image info test => (${FUNCNAME[@]})"

  check_valgrind_log
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && return ${FAILURE}

  msg_info "${test} starting..."
  cp /etc/isulad/daemon.json /etc/isulad/daemon.bak
  sed -i "/registry-mirrors/a\        \"docker.io\"," /etc/isulad/daemon.json

  start_isulad_with_valgrind
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && return ${FAILURE}

  isula search ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search image: ${image}" && return ${FAILURE}
  
  isula search ${invalid_image} 2>&1 | grep "Invalid search name"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  search  ${invalid_image} should fail as it's search name is invalid" && return ${FAILURE}

  isula search "" 2>&1 | grep "error"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} -  search  ${invalid_image} should fail as it's search name is invalid" && return ${FAILURE}

  # test search options   
  isula search --no-trunc ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search images with no-trunc: ${image}" && ((ret++))

  isula search --limit 5 ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search images with limit: ${image}" && ((ret++))

  isula search --limit -1 ${image} 2>&1 | grep "Invalid value"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search images with limit: ${image} and and catch error msg" && ((ret++))

  isula search --filter stars=3 ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search images with filter stars: ${image}" && ((ret++))

  isula search --filter is-official=true ${image}
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search images with filter is-official: ${image}" && ((ret++))

  isula search --filter is-automated=true ${image} 2>&1 | grep "AUTOMATED"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search images with filter is-automated: ${image}" && ((ret++))

  isula search --filter aa=true ${image} 2>&1 | grep "Invalid filter"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set filter for search ${image} and catch error msg" && ((ret++))

  isula search ${image} 2>&1 | grep "NAME"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search images with default table format: ${image}" && ((ret++))

  isula search --format "table {{.IsAutomated}}\t{{.IsOfficial}}" ${image} 2>&1 | grep "AUTOMATED"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search images with table format: ${image}" && ((ret++))

  isula search --format "{{Name}}" ${image} 2>&1 | grep "invalid format field"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to set format for search ${image} and catch error msg" && ((ret++))

  isula search --format "{{.Name}}" ${image} 2>&1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to search images with none-table format: ${image}" && ((ret++))

  cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json

  check_valgrind_log
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && return ${FAILURE}
  
  start_isulad_with_valgrind
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && return ${FAILURE}

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_image_search || ((ans++))

show_result ${ans} "${curr_path}/${0}"

