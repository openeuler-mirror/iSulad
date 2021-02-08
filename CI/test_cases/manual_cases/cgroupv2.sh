#!/bin/bash
#
# attributes: isulad cgroupv2
# concurrent: YES
# spend time: 15

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
##- @Author: wangfengtu
##- @Create: 2021-01-26
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
test="cgroupv2 test => test_cgroupv2"
cgroupv2=0
cgroup2_update="cgroup2_update"

function test_cgroup2_cpu()
{
  local ret=0

  if [[ -f /sys/fs/cgroup/isulad/cpu.weight ]];then
    # min value
    isula run -ti --rm --cpu-shares 2 busybox cat /sys/fs/cgroup/cpu.weight | grep ^1$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.weight min value failed" && ((ret++))

    # max value
    isula run -ti --rm --cpu-shares 262144 busybox cat /sys/fs/cgroup/cpu.weight | grep ^10000$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.weight max value failed" && ((ret++))

    # invalid value
    isula run -ti --rm --cpu-shares -1 busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.weight -1 failed" && ((ret++))

    # default value
    isula run -ti --rm --cpu-shares 0 busybox cat /sys/fs/cgroup/cpu.weight | grep ^100$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.weight default value failed" && ((ret++))
  fi

  if [[ -f /sys/fs/cgroup/isulad/cpu.max ]];then
    # normal value
    isula run -ti --rm --cpu-quota 50000 --cpu-period 12345 busybox cat /sys/fs/cgroup/cpu.max | grep ^"50000 12345"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.max normal value failed" && ((ret++))

    # invalid min period
    isula run -ti --rm --cpu-quota 50000 --cpu-period 999 busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.max invalid min period failed" && ((ret++))

    # invalid max period
    isula run -ti --rm --cpu-quota 50000 --cpu-period 1000001 busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.max invalid max period failed" && ((ret++))

    # invalid quota
    isula run -ti --rm --cpu-quota 999 --cpu-period 1000000 busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.max invalid quota failed" && ((ret++))

    # default 0 quota
    isula run -ti --rm --cpu-quota 0 --cpu-period 1000000 busybox cat /sys/fs/cgroup/cpu.max | grep ^"max 1000000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.max default 0 quota failed" && ((ret++))

    # default -1 quota
    isula run -ti --rm --cpu-quota -1 --cpu-period 1000000 busybox cat /sys/fs/cgroup/cpu.max | grep ^"max 1000000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.max default -1 quota failed" && ((ret++))

    # cpus 1
    isula run -ti --rm --cpus 1 busybox cat /sys/fs/cgroup/cpu.max | grep ^"100000 100000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.max cpus 1 failed" && ((ret++))

    # cpus 0
    isula run -ti --rm --cpus 0 busybox cat /sys/fs/cgroup/cpu.max | grep ^"max 100000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpu.max cpus 0 failed" && ((ret++))
  fi

  if [[ -f /sys/fs/cgroup/isulad/cpuset.cpus.effective ]];then
    # normal value
    isula run -tid -n cpuset --cpuset-cpus 0 --cpuset-mems 0 busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpuset run container failed" && ((ret++))

    isula exec -ti cpuset cat /sys/fs/cgroup/cpuset.cpus | grep ^0$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpuset value not right" && ((ret++))

    isula exec -ti cpuset cat /sys/fs/cgroup/cpuset.mems | grep ^0$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpuset value not right" && ((ret++))

    isula rm -f cpuset
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpuset remove container failed" && ((ret++))

    # invalid cpus -1 value
    isula run -tid -n cpuset --cpuset-cpus -1 busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpuset cpus invalid -1 failed" && ((ret++))

    # invalid cpus 100000 value
    isula run -tid -n cpuset --cpuset-cpus 100000 busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpuset cpus invalid 100000 failed" && ((ret++))

    # invalid mems -1 value
    isula run -tid -n cpuset --cpuset-mems -1 busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpuset mems invalid -1 failed" && ((ret++))

    # invalid mems 100000 value
    isula run -tid -n cpuset --cpuset-mems 100000 busybox sh
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 cpuset mems invalid 100000 failed" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_io()
{
  local ret=0

  if [[ -f "/sys/fs/cgroup/isulad/io.bfq.weight" ]];then
    # min value
    isula run -ti --rm --blkio-weight 10 busybox cat "/sys/fs/cgroup/io.bfq.weight" | grep 1$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.bfq.weight min value failed" && ((ret++))

    # max value
    isula run -ti --rm --blkio-weight 1000 busybox cat "/sys/fs/cgroup/io.bfq.weight" | grep 1000$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.bfq.weight max value failed" && ((ret++))

    # default value
    isula run -ti --rm --blkio-weight 0 busybox cat "/sys/fs/cgroup/io.bfq.weight" | grep 100$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.bfq.weight default value failed" && ((ret++))

    # invalid value
    isula run -ti --rm --blkio-weight -1 busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.bfq.weight -1 failed" && ((ret++))
  fi

  if [[ -f "/sys/fs/cgroup/isulad/io.bfq.weight_device" ]];then
    # min value
    isula run -ti --rm --blkio-weight-device /dev/null:10 busybox cat "/sys/fs/cgroup/io.bfq.weight_device" | grep ^"1:3 10"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.bfq.weight_device max value failed" && ((ret++))

    # max value
    isula run -ti --rm --blkio-weight-device /dev/null:1000 busybox cat "/sys/fs/cgroup/io.bfq.weight_device" | grep ^"1:3 10000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.bfq.weight_device max value failed" && ((ret++))

    # disable weight device
    isula run -tid -n weight_device --rm --blkio-weight-device /dev/null:0 busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.bfq.weight_device failed" && ((ret++))

    isula exec -ti weight_device cat "/sys/fs/cgroup/io.bfq.weight_device" | grep "1:3"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.bfq.weight_device disable failed" && ((ret++))

    isula rm -f weight_device
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.bfq.weight_device remove container failed" && ((ret++))
  fi

  if [[ -f "/sys/fs/cgroup/isulad/io.weight" ]];then
    # min value
    isula run -ti --rm --blkio-weight 10 busybox cat "/sys/fs/cgroup/io.weight" | grep ^"default 1"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.weight min value failed" && ((ret++))

    # max value
    isula run -ti --rm --blkio-weight 1000 busybox cat "/sys/fs/cgroup/io.weight" | grep ^"default 10000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.weight max value failed" && ((ret++))

    # default value
    isula run -ti --rm --blkio-weight 0 busybox cat "/sys/fs/cgroup/io.weight" | grep ^"default 100"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.weight default value failed" && ((ret++))

    # invalid value
    isula run -ti --rm --blkio-weight -1 busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.weight -1 failed" && ((ret++))
  fi

  if [[ -f "/sys/fs/cgroup/isulad/io.weight_device" ]];then
    # min value
    isula run -ti --rm --blkio-weight-device /dev/null:10 busybox cat "/sys/fs/cgroup/io.weight_device" | grep ^"1:3 10"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.weight max value failed" && ((ret++))

    # max value
    isula run -ti --rm --blkio-weight-device /dev/null:1000 busybox cat "/sys/fs/cgroup/io.weight_device" | grep ^"1:3 10000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.weight max value failed" && ((ret++))

    # disable weight device
    isula run -tid -n weight_device --rm --blkio-weight-device /dev/null:0 busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.weight failed" && ((ret++))

    isula exec -ti weight_device cat "/sys/fs/cgroup/io.weight_device" | grep ^"1:3"$'\r'
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.weight disable failed" && ((ret++))

    isula rm -f weight_device
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.weight remove container failed" && ((ret++))
  fi

  if [[ -f /sys/fs/cgroup/isulad/io.max ]];then
    # normal value
    isula run -ti --rm --device-read-bps /dev/null:1g --device-read-iops /dev/null:1000 --device-write-bps /dev/null:2g --device-write-iops /dev/null:2000 busybox cat /sys/fs/cgroup/io.max | grep ^"1:3 rbps=1073741824 wbps=2147483648 riops=1000 wiops=2000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.max failed" && ((ret++))

    # invalid
    isula run -ti --rm --device-read-bps /dev/null:-1 busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.max -1 failed" && ((ret++))

    # 0 is no limit
    isula run -ti --rm --device-read-bps /dev/null:0 --device-read-iops /dev/null:0 --device-write-bps /dev/null:0 --device-write-iops /dev/null:0 busybox echo hello
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 io.max 0 failed" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_memory()
{
  local ret=0

  if [[ -f /sys/fs/cgroup/isulad/memory.max ]];then
    # normal value
    isula run -ti --rm -m 10m busybox cat /sys/fs/cgroup/memory.max | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.max run container failed" && ((ret++))

    # 0 is max
    isula run -ti --rm -m 0 busybox cat /sys/fs/cgroup/memory.max | grep ^max$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.max 0 failed" && ((ret++))

    # invalid
    isula run -ti --rm -m -1 busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.max -1 failed" && ((ret++))
  fi

  if [[ -f /sys/fs/cgroup/isulad/memory.low ]];then
    # normal value
    isula run -ti --rm --memory-reservation 10m busybox cat /sys/fs/cgroup/memory.low | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.low normal value failed" && ((ret++))

    # -1 is invalid
    isula run -ti --rm --memory-reservation -1 busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.low invalid failed" && ((ret++))

    # 0
    isula run -ti --rm --memory-reservation 0 busybox cat /sys/fs/cgroup/memory.low | grep ^0$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.low 0 failed" && ((ret++))
  fi

  if [[ -f /sys/fs/cgroup/isulad/memory.swap.max ]];then
    # normal value
    isula run -ti --rm --memory 10m --memory-swap 20m busybox cat /sys/fs/cgroup/memory.swap.max | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.swap.max normal value failed" && ((ret++))

    # invalid
    isula run -ti --rm --memory 10m --memory-swap 5m busybox echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.swap.max invalid failed" && ((ret++))

    # 0 is the same as memory
    isula run -ti --rm --memory 10m --memory-swap 0 busybox cat /sys/fs/cgroup/memory.swap.max | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.swap.max 0 failed" && ((ret++))

    # -1 is max
    isula run -ti --rm --memory 10m --memory-swap -1 busybox cat /sys/fs/cgroup/memory.swap.max | grep ^max$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.swap.max -1 failed" && ((ret++))

    # disable swap
    isula run -ti --rm --memory 10m --memory-swap 10m busybox cat /sys/fs/cgroup/memory.swap.max | grep ^0$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 memory.swap.max disable swap failed" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_pids()
{
  local ret=0

  if [[ -f /sys/fs/cgroup/isulad/pids.max ]];then
    # normal value
    isula run -ti --rm --pids-limit 123456 busybox cat /sys/fs/cgroup/pids.max | grep ^123456$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 pids.max run container failed" && ((ret++))

    # -1 is max
    isula run -ti --rm --pids-limit -1 busybox cat /sys/fs/cgroup/pids.max | grep ^max$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 pids.max run container failed" && ((ret++))

    # 0 is max
    isula run -ti --rm --pids-limit 0 busybox cat /sys/fs/cgroup/pids.max | grep ^max$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 pids.max run container failed" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_hugetlb()
{
  local ret=0

  if [[ -f /sys/fs/cgroup/isulad/hugetlb.2MB.max ]];then
    isula run -ti --rm --hugetlb-limit 2M:32M busybox cat /sys/fs/cgroup/hugetlb.2MB.max | grep ^33554432$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 hugetlb.2M.max run container failed" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_freeze()
{
  local ret=0

  if [[ -f /sys/fs/cgroup/isulad/cgroup.freeze ]];then
    isula run -tid -n freeze busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 freeze run container failed" && ((ret++))

    isula pause freeze
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 freeze pause container failed" && ((ret++))

    isula exec -ti freeze echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 freeze pause take no effect" && ((ret++))

    isula unpause freeze
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 freeze unpause container failed" && ((ret++))

    isula exec -ti freeze echo hello
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 freeze unpause take no effect" && ((ret++))

    isula rm -f freeze
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 freeze remove container failed" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_files()
{
  local ret=0

  if [[ -f /sys/fs/cgroup/isulad/files.limit ]];then
    # normal value
    isula run -ti --rm --files-limit 123 busybox cat /sys/fs/cgroup/files.limit | grep ^123$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 files.limit run container failed" && ((ret++))

    # -1 is max
    isula run -ti --rm --files-limit -1 busybox cat /sys/fs/cgroup/files.limit | grep ^max$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 files.limit run container failed" && ((ret++))

    # 0 is max
    isula run -ti --rm --files-limit 0 busybox cat /sys/fs/cgroup/files.limit | grep ^max$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 files.limit run container failed" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_cpu_update()
{
  local ret=0

  if [[ -f /sys/fs/cgroup/isulad/cpu.weight ]];then
    # min value
    isula update --cpu-shares 2 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.weight min value failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/cpu.weight | grep ^1$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.weight min value not right" && ((ret++))

    # max value
    isula update --cpu-shares 262144 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.weight max value failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/cpu.weight | grep ^10000$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.weight max value not right" && ((ret++))

    # 0 means not change
    isula update --cpu-shares 0 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.weight 0 failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/cpu.weight | grep ^10000$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.weight 0 not right" && ((ret++))

    # invalid value
    isula update --cpu-shares -1 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.weight -1 failed" && ((ret++))
  fi

  if [[ -f /sys/fs/cgroup/isulad/cpu.max ]];then
    # normal value
    isula update --cpu-quota 50000 --cpu-period 12345 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max normal value failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/cpu.max | grep ^"50000 12345"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max normal value not right" && ((ret++))

    # invalid min period
    isula update --cpu-quota 50000 --cpu-period 999 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max invalid min period failed" && ((ret++))

    # invalid max period
    isula update --cpu-quota 50000 --cpu-period 1000001 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max invalid max period failed" && ((ret++))

    # invalid quota
    isula update --cpu-quota 999 --cpu-period 1000000 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max invalid quota failed" && ((ret++))

    # default 0 quota
    isula update --cpu-quota 0 --cpu-period 1000000 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max 0 quota failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/cpu.max | grep ^"max 1000000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max 0 quota value not right" && ((ret++))

    # default -1 quota
    isula update --cpu-quota -1 --cpu-period 1000000 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max -1 quota failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/cpu.max | grep ^"max 1000000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max -1 quota value not right" && ((ret++))

    # cpus 1
    isula run -tid -n cpu_update busybox sh
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 run cpu_update failed" && ((ret++))

    isula update --cpus 1 cpu_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max cpus 1 failed" && ((ret++))

    isula exec -ti cpu_update cat /sys/fs/cgroup/cpu.max | grep ^"100000 100000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max cpus 1 value not right" && ((ret++))

    # cpus 0 means not change
    isula update --cpus 0 cpu_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max cpus 0 failed" && ((ret++))

    isula exec -ti cpu_update cat /sys/fs/cgroup/cpu.max | grep ^"100000 100000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpu.max cpus 0 value not right" && ((ret++))

    isula rm -f cpu_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 remove cpu_update failed" && ((ret++))
  fi

  if [[ -f /sys/fs/cgroup/isulad/cpuset.cpus.effective ]];then
    # normal value
    isula update --cpuset-cpus 0 --cpuset-mems 0 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update update cpuset failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/cpuset.cpus | grep -E ^0$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpuset.cpus value not right" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/cpuset.mems | grep -E ^0$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpuset.mems value not right" && ((ret++))

    # invalid cpus -1 value
    isula update --cpuset-cpus -1 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpuset.cpus invalid -1 failed" && ((ret++))

    # invalid cpus 100000 value
    isula update --cpuset-cpus 100000 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpuset.cpus invalid 100000 failed" && ((ret++))

    # invalid mems -1 value
    isula update --cpuset-mems -1 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpuset.mems invalid -1 failed" && ((ret++))

    # invalid mems 100000 value
    isula update --cpuset-mems 100000 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update cpuset.mems invalid 100000 failed" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_io_update()
{
  local ret=0

  if [[ -f "/sys/fs/cgroup/isulad/io.bfq.weight" ]];then
    # min value
    isula update --blkio-weight 10 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.bfq.weight min value failed" && ((ret++))

    isula exec -ti $cgroup2_update cat "/sys/fs/cgroup/io.bfq.weight" | grep 1$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.bfq.weight min value not right" && ((ret++))

    # max value
    isula update --blkio-weight 1000 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.bfq.weight max value failed" && ((ret++))

    isula exec -ti $cgroup2_update cat "/sys/fs/cgroup/io.bfq.weight" | grep 1000$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.bfq.weight max value not right" && ((ret++))

    # 0 means value not change
    isula update --blkio-weight 0 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.bfq.weight 0 failed" && ((ret++))

    isula exec -ti $cgroup2_update cat "/sys/fs/cgroup/io.bfq.weight" | grep 1000$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.bfq.weight 0 not right" && ((ret++))

    # invalid value
    isula update --blkio-weight -1 $cgroup2_update echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.bfqweight -1 failed" && ((ret++))
  fi

  if [[ -f "/sys/fs/cgroup/isulad/io.weight" ]];then
    # min value
    isula update --blkio-weight 10 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.weight min value failed" && ((ret++))

    isula exec -ti $cgroup2_update cat "/sys/fs/cgroup/io.weight" | grep ^"default 1"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.weight min value not right" && ((ret++))

    # max value
    isula update --blkio-weight 1000 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.weight max value failed" && ((ret++))

    isula exec -ti $cgroup2_update cat "/sys/fs/cgroup/io.weight" | grep ^"default 10000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.weight max value not right" && ((ret++))

    # 0 means value not change
    isula update --blkio-weight 0 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.weight 0 failed" && ((ret++))

    isula exec -ti $cgroup2_update cat "/sys/fs/cgroup/io.weight" | grep ^"default 10000"$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.weight 0 not right" && ((ret++))

    # invalid value
    isula update --blkio-weight -1 $cgroup2_update echo hello
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update io.weight -1 failed" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_memory_update()
{
  local ret=0

  if [[ -f /sys/fs/cgroup/isulad/memory.max ]];then
    # normal value
    isula update -m 10m $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.max 10m failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/memory.max | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.max 10m value not right" && ((ret++))

    # 0 is not change
    isula update -m 0 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.max 0 failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/memory.max | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.max 0 not right" && ((ret++))

    # invalid
    isula update -m -1 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.max -1 failed" && ((ret++))
  fi

  if [[ -f /sys/fs/cgroup/isulad/memory.low ]];then
    # normal value
    isula update --memory-reservation 10m $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.low normal value failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/memory.low | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.low normal value not right" && ((ret++))

    # 0 means not change
    isula update --memory-reservation 0 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.low 0 failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/memory.low | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.low 0 value not right" && ((ret++))

    # -1 is invalid
    isula update --memory-reservation -1 $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.low invalid failed" && ((ret++))
  fi

  if [[ -f /sys/fs/cgroup/isulad/memory.swap.max ]];then
    # normal value
    isula update --memory 10m --memory-swap 20m $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.swap.max normal value failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/memory.swap.max | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.swap.max normal value not right" && ((ret++))

    # invalid
    isula update --memory 10m --memory-swap 5m $cgroup2_update
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.swap.max invalid failed" && ((ret++))

    # 0 is the same as memory
    isula update --memory 10m --memory-swap 0 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.swap.max 0 failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/memory.swap.max | grep ^10485760$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.swap.max 0 value not right" && ((ret++))

    # -1 is max
    isula update --memory 10m --memory-swap -1 $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.swap.max -1 failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/memory.swap.max | grep ^max$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.swap.max -1 value not right" && ((ret++))

    # disable swap
    isula update --memory 10m --memory-swap 10m $cgroup2_update
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.swap.max disable swap failed" && ((ret++))

    isula exec -ti $cgroup2_update cat /sys/fs/cgroup/memory.swap.max | grep ^0$'\r'
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update memory.swap.max disable swap value not right" && ((ret++))
  fi

  return ${ret}
}

function test_cgroup2_unsupported()
{
  local ret=0

  isula run -ti --rm --cpu-rt-period 1000000 --cpu-rt-runtime 1000000 busybox echo hello
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --cpu-rt-period and --cpu-rt-runtime should failed" && ((ret++))

  isula run -ti --rm --kernel-memory 100m busybox echo hello
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --kernel-memory should failed" && ((ret++))

  isula run -ti --rm --memory-swappiness 50 busybox echo hello
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --memory-swappiness should failed" && ((ret++))

  isula run -ti --rm --oom-kill-disable busybox echo hello
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --oom-kill-disable should failed" && ((ret++))

  isula update --cpu-rt-period 1000000 --cpu-rt-runtime 1000000 $cgroup2_update
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update --cpu-rt-period and --cpu-rt-runtime should failed" && ((ret++))

  isula update --kernel-memory 100m $cgroup2_update
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 update --kernel-memory should failed" && ((ret++))

  return ${ret}
}

function test_cgroup2_parent()
{
  local ret=0

  rmdir /sys/fs/cgroup/isulad
  rmdir /sys/fs/cgroup/abc

  id=`isula run -tid --cgroup-parent /abc -m 10m busybox sh`
  cat /sys/fs/cgroup/abc/$id/memory.max | grep ^10485760$
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --cgroup-parent cannot work" && ((ret++))

  return ${ret}
}

function test_cgroup2_device()
{
  local ret=0

  dev_name=/dev/$(lsblk | grep disk | head -n 1 | awk '{print $1}')
  dev_num=$(lsblk | grep disk | head -n 1 | awk '{print $2}')
  mknod_num=$(echo $dev_num | sed 's/:/ /g')

  # read only
  isula run -ti --rm --device=$dev_name:/dev/sdx:r busybox sh -c 'echo q | fdisk /dev/sdx | grep "read only"'
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device r failed" && ((ret++))

  isula run -ti --rm --device=$dev_name:/dev/sdx:rm busybox sh -c 'echo q | fdisk /dev/sdx | grep "read only"'
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device rm failed" && ((ret++))

  isula run -ti --rm --device-cgroup-rule="b $dev_num r" busybox sh -c "mknod /dev/sdx b $mknod_num && echo q | fdisk /dev/sdx | grep 'read only'"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device r failed" && ((ret++))

  isula run -ti --rm --device-cgroup-rule="b $dev_num rm" busybox sh -c "mknod /dev/sdx b $mknod_num && echo q | fdisk /dev/sdx | grep 'read only'"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device rm failed" && ((ret++))

  # can't read
  isula run -ti --rm --device=$dev_name:/dev/sdx:w busybox sh -c 'echo q | fdisk /dev/sdx 2>&1 | grep "t open"'
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device w failed" && ((ret++))

  isula run -ti --rm --device=$dev_name:/dev/sdx:wm busybox sh -c 'echo q | fdisk /dev/sdx 2>&1 | grep "t open"'
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device wm failed" && ((ret++))

  isula run -ti --rm --device-cgroup-rule="b $dev_num w" busybox sh -c "mknod /dev/sdx b $mknod_num && echo q | fdisk /dev/sdx 2>&1 | grep 't open'"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device w failed" && ((ret++))

  isula run -ti --rm --device-cgroup-rule="b $dev_num wm" busybox sh -c "mknod /dev/sdx b $mknod_num && echo q | fdisk /dev/sdx 2>&1 | grep 't open'"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device wm failed" && ((ret++))

  # can't read write
  isula run -ti --rm --device=$dev_name:/dev/sdx:m busybox sh -c 'echo q | fdisk /dev/sdx 2>&1 | grep "t open"'
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device m" && ((ret++))

  isula run -ti --rm --device-cgroup-rule="b $dev_num m" busybox sh -c "mknod /dev/sdx b $mknod_num && echo q | fdisk /dev/sdx 2>&1 | grep 't open'"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device wm failed" && ((ret++))

  isula run -ti --rm --device-cgroup-rule="b *:* m" busybox sh -c "mknod /dev/sdx b $mknod_num && echo q | fdisk /dev/sdx 2>&1 | grep 't open'"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 --device wm failed" && ((ret++))

  return ${ret}
}

function prepare_test_cgroupv2()
{
  local ret=0

  cat /proc/1/mountinfo | grep "\- cgroup2" | grep "/sys/fs/cgroup rw"
  if [ x"$?" == x"0" ];then
    cgroupv2=1
  else
    return 0
  fi

  all=$(cat /sys/fs/cgroup/cgroup.controllers)
  sub=$(cat /sys/fs/cgroup/cgroup.subtree_control)
  if [ x"$all" != x"$sub" ];then
    echo +cpuset > /sys/fs/cgroup/cgroup.subtree_control
    echo +cpu > /sys/fs/cgroup/cgroup.subtree_control
    echo +io > /sys/fs/cgroup/cgroup.subtree_control
    echo +memory > /sys/fs/cgroup/cgroup.subtree_control
    echo +pids > /sys/fs/cgroup/cgroup.subtree_control
    echo +hugetlb > /sys/fs/cgroup/cgroup.subtree_control
    echo +files > /sys/fs/cgroup/cgroup.subtree_control
  fi

  mkdir -p /sys/fs/cgroup/isulad
  chmod 755 /sys/fs/cgroup/isulad

  isula rm -f `isula ps -a -q`

  isula run -tid -n $cgroup2_update busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - cgroup2 run container failed" && ((ret++))

  return ${ret}
}

function post_test_cgroupv2()
{
  isula rm -f `isula ps -a -q`
  return 0
}

declare -i ans=0

msg_info "${test} starting..."
[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

prepare_test_cgroupv2 || ((ans++))
if [ "$cgroupv2" == "1" ];then
  test_cgroup2_cpu || ((ans++))
  test_cgroup2_io || ((ans++))
  test_cgroup2_memory || ((ans++))
  test_cgroup2_pids || ((ans++))
  test_cgroup2_hugetlb || ((ans++))
  test_cgroup2_freeze || ((ans++))
  test_cgroup2_files || ((ans++))
  test_cgroup2_cpu_update || ((ans++))
  test_cgroup2_io_update || ((ans++))
  test_cgroup2_memory_update || ((ans++))
  test_cgroup2_unsupported || ((ans++))
  test_cgroup2_parent || ((ans++))
  test_cgroup2_device || ((ans++))
else
  msg_info "${test} not cgroup v2 enviorment, ignore test..."
fi
post_test_cgroupv2

msg_info "${test} finished with return ${ans}..."

show_result ${ans} "${curr_path}/${0}"
