#!/bin/bash
#
# attributes: isulad basic cri seccomp
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
##- @Author: wangfengtu
##- @Create: 2022-08-13
#######################################################################

source ../helpers.sh
curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/criconfigs)
pause_img_path=$(realpath $curr_path/test_data)

function do_pre()
{
  sed -i "s#seccomp_localhost_ref#${data_path}/seccomp_localhost.json#g" ${data_path}/container-config-seccomp-localhost.json

  cp /etc/isulad/daemon.json /etc/isulad/daemon.bak
  sed -i "s#\"pod-sandbox-image\": \"\"#\"pod-sandbox-image\": \"mirrorgooglecontainers/pause-amd64:3.0\"#g" /etc/isulad/daemon.json

  check_valgrind_log
  start_isulad_with_valgrind

  isula load -i ${pause_img_path}/pause.tar
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to load pause" && return ${FAILURE}
}

function do_post()
{
    cp -f /etc/isulad/daemon.bak /etc/isulad/daemon.json
    check_valgrind_log
    start_isulad_with_valgrind
}

function test_cri_seccomp()
{
  local ret=0
  local image="busybox"
  local test="cri seccomp test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula rm -f `isula ps -a -q`

  sid=`crictl runp ${data_path}/sandbox_config3.json`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to runp sandbox" && return ${FAILURE}

  cid=`crictl create $sid ${data_path}/"container-config-seccomp-"$1".json" ${data_path}/sandbox_config3.json`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create container for $1" && ((ret++))

  crictl start $cid
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to start container for $1" && ((ret++))

  if [ "$1" == "unconfined" ]; then
    isula exec -ti $cid sh -c "grep Seccomp /proc/self/status | head -n 1 | grep 0"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - seccomp enable should be 0" && ((ret++))
    isula exec -ti $cid sh -c "chmod 777 /home"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - chmod should success" && ((ret++))
  elif [ "$1" == "default" ];then
    isula exec -ti $cid sh -c "grep Seccomp /proc/self/status | head -n 1 | grep 0"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - seccomp enable should not be 0 when default" && ((ret++))
  elif [ "$1" == "localhost" ];then
    isula exec -ti $cid sh -c "grep Seccomp /proc/self/status | head -n 1 | grep 0"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - seccomp enable should not be 0 when localhost" && ((ret++))
    isula exec -ti $cid sh -c "chmod 777 /home"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - chmod should fail as it's blocked by seccomp" && ((ret++))
  fi

  isula rm -f `isula ps -a -q`

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

do_pre

test_cri_seccomp "default" || ((ans++))
test_cri_seccomp "unconfined" || ((ans++))
test_cri_seccomp "localhost" || ((ans++))

do_post

show_result ${ans} "${curr_path}/${0}"

