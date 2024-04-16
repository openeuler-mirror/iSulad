#!/bin/bash
#
# attributes: isulad basic image
# concurrent: NA
# spend time: 22

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
##- @Author: gaohuatao
##- @Create: 2020-05-14
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
single_image="${curr_path}/busybox.tar"
mult_image="${curr_path}/mult_image.tar"

function test_image_load()
{
  local ret=0
  local test="isula load image test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  # file is not exist, expect fail
  isula load -i xxx.tar
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - image tar file not exist test failed" && ((ret++))


  # single image without --tag
  isula load -i $single_image
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load image failed: ${single_image}" && ((ret++))

  isula images | grep busybox
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: busybox" && ((ret++))

  id=`isula inspect -f '{{.image.id}}' busybox`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to inspect image busybox" && ((ret++))

  # single image with --tag
  isula load -i $single_image --tag "kitty"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load image failed: ${single_image} with --tag kitty" && ((ret++))

  isula images | grep kitty
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: kitty" && ((ret++))

  isula rmi $id
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image ${id}" && ((ret++))


  # multi images without --tag
  isula load -i $mult_image
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load image failed: ${mult_image}" && ((ret++))

  ubuntu_id=`isula inspect -f '{{.image.id}}' ubuntu`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to inspect image: ubuntu" && ((ret++))

  busybox_id=`isula inspect -f '{{.image.id}}' busybox`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to inspect image: busybox" && ((ret++))

  isula rmi $ubuntu_id $busybox_id
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image ${ubuntu_id} and ${busybox_id}" && ((ret++))

  # multi images with --tag
  isula load -i $mult_image --tag "correct_tag_name"
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load multi images :${mult_image} with --tag correct_tag_name not get fail" && ((ret++))


  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

function test_concurrent_load()
{
  local ret=0
  local test="isula load image test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  # clean exist image
  ubuntu_id=`isula inspect -f '{{.image.id}}' ubuntu`
  busybox_id=`isula inspect -f '{{.image.id}}' busybox`
  isula rmi $ubuntu_id $busybox_id

  concurrent_time=10
  for i in `seq 1 $concurrent_time`
  do
      isula load -i $mult_image &
      pids[$i]=$!
  done

  for i in `seq 1 $concurrent_time`;do
      wait ${pids[$i]}
      [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to do isulad load $i" && ((ret++))
  done

  tail -n 50 /var/lib/isulad/isulad.log

  ubuntu_id=`isula inspect -f '{{.image.id}}' ubuntu`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to inspect image: ubuntu" && ((ret++))

  top_layer_id=$(isula inspect -f '{{.image.top_layer}}' ${ubuntu_id})

  busybox_id=`isula inspect -f '{{.image.id}}' busybox`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to inspect image: busybox" && ((ret++))

  # delete image after concurrent load
  isula rmi $ubuntu_id $busybox_id
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove image ${ubuntu_id} and ${busybox_id}" && ((ret++))

  ls -l /var/lib/isulad/storage/overlay-layers
  local top_layer_dir=/var/lib/isulad/storage/overlay-layers/${top_layer_id}
  test -e ${top_layer_dir}
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - top layer dir ${top_layer_id} exist after delete image" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_concurrent_load || ((ans++))

test_image_load || ((ans++))

show_result ${ans} "${curr_path}/${0}"

