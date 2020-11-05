#!/bin/bash
#
# attributes: isulad volume
# concurrent: YES
# spend time: 3

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
##- @Create: 2020-08-31
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_volume()
{
  local ret=0
  local test="volume test => (${FUNCNAME[@]})"

  msg_info "${test} starting..."

  isula rm -f `isula ps -a -q`

  # test command name of help
  isula --help | grep volume
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula --help failed" && ((ret++))

  isula volume --help | grep "isula volume"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula volume --help failed" && ((ret++))

  isula volume rm --help | grep "isula volume rm"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isula volume rm --help failed" && ((ret++))

  # test anonymous volume
  isula run -tid --name vol1 -v /vol busybox touch /vol/test
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run vol1 container" && ((ret++))

  isula rm -f vol1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove vol1 container" && ((ret++))

  # test named volume
  isula run -tid -v vol:/vol busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with named volume" && ((ret++))

  # test remove volume
  isula rm -f `isula ps -a -q`
  isula volume rm vol
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove specified volume" && ((ret++))

  # test volume restore
  isula run -tid --name restore -v vol_restore:/vol busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container for restore volume" && ((ret++))

  isula exec -ti restore touch /vol/restore.txt
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create file for restore volume" && ((ret++))

  check_valgrind_log
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stop isulad failed" && ((ret++))

  start_isulad_with_valgrind
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

  isula exec -ti restore cat /vol/restore.txt
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to restore volume" && ((ret++))

  # test -v readonly
  isula run -tid --name readonly -v vol:/vol:ro busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with -v readonly volume" && ((ret++))

  isula exec -ti readonly dd if=/dev/zero of=/vol/readonly bs=1k count=1
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - dd to -v readonly volume should fail" && ((ret++))

  # test --mount readonly
  isula run -tid --name readonly2 --mount type=volume,src=vol,dst=/vol,readonly=true busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with --mount readonly volume" && ((ret++))

  isula exec -ti readonly2 dd if=/dev/zero of=/vol/readonly bs=1k count=1
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - dd to --mount readonly volume should fail" && ((ret++))

  # test anonymous volume in image config
  isula load -i test_data/vol.tar
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to load image with volume" && ((ret++))

  isula run -tid --name vol2 vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run image with volume" && ((ret++))

  isula exec -ti vol2 stat /vol
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - vol1 not found" && ((ret++))

  isula exec -ti vol2 stat /vol2
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - vol2 not found" && ((ret++))

  isula rm -f vol2
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove vol2 container" && ((ret++))

  # test mounts destination conflict condition 1 -v vs image config volume
  isula run -tid --name vol3 -v vol3:/vol vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with conflict destination should fail condition 1" && ((ret++))

  nums=`isula inspect -f "{{.Mounts}}" vol3 | grep _data | wc -l`
  [[ $nums -ne 2 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run image with volume" && ((ret++))

  isula inspect -f "{{.Mounts}}" vol3 | grep vol3
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run image with volume" && ((ret++))

  isula rm -f vol3
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove vol3 container" && ((ret++))

  # test mounts destination conflict condition 2 -v vs --mount
  isula run -tid --name vol4 -v /vol --mount type=volume,destination=/vol busybox sh
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with conflict destination should fail condition 2" && ((ret++))

  # test mounts destination conflict condition 3 -v vs -v
  isula run -tid --name vol5 -v vol5:/vol5 -v /home:/vol5 busybox sh
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with conflict destination should fail condition 3" && ((ret++))

  # test --rm can remove anonymous volume but not non-anonymous
  isula run --rm -ti --name vol6 -v vol6:/vol6 vol echo vol6
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with non-anonymous failed" && ((ret++))

  isula inspect vol6
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - container vol6 still exist after container stopped" && ((ret++))

  # clean up
  isula rm -f `isula ps -a -q`
  echo y | isula volume prune
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to prune volumes" && ((ret++))

  # test prune can not remove used volume
  isula run -ti --name vol7 -v vol7:/vol7 vol echo vol7
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run image with non-anonymous failed" && ((ret++))

  n1=`isula volume ls -q | wc -l`
  [[ $n1 -ne 3 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - volume number not right" && ((ret++))

  isula volume prune -f
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to prune volumes" && ((ret++))

  n2=`isula volume ls -q | wc -l`
  [[ $n2 -ne 3 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - volume number not right after prune" && ((ret++))

  # test prune can remove all volumes unused
  isula rm -f `isula ps -a -q`
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to remove all containers" && ((ret++))

  isula volume prune -f
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to prune volumes" && ((ret++))

  n3=`isula volume ls -q | wc -l`
  [[ $n3 -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - volume not all removed after prune" && ((ret++))

  # test two container use one same volume
  isula run -tid --name vol8_1 -v vol8:/vol8 vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container vol8_1 failed" && ((ret++))

  isula run -tid --name vol8_2 -v vol8:/vol8 vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container vol8_2 failed" && ((ret++))

  isula rm -f vol8_1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - remove container vol8_1 failed" && ((ret++))

  isula volume prune -f
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to prune volumes" && ((ret++))

  n4=`isula volume ls -q | wc -l`
  [[ $n4 -ne 3 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - volume number not right after prune" && ((ret++))

  isula rm -f vol8_2
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - remove container vol8_2 failed" && ((ret++))

  isula volume prune -f
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to prune volumes" && ((ret++))

  n5=`isula volume ls -q | wc -l`
  [[ $n5 -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - volume number not right after prune" && ((ret++))

  # test --mount with volume binds
  isula run -tid --name vol9 --mount type=volume,source=vol9,destination=/vol9 vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container vol9 failed" && ((ret++))

  isula volume ls | grep vol9
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to found volume vol9" && ((ret++))

  # test nocopy
  isula run -ti --rm --mount target=/usr,volume-nocopy=true vol echo hello
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - nocopy parameter of --mount start container failed" && ((ret++))

  isula run -ti --rm --mount target=/usr,volume-nocopy=true,bind-selinux-opts=z vol stat /usr/sbin
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - nocopy parameter of --mount take no effect" && ((ret++))

  isula run -ti --rm -v test:/usr:nocopy vol echo hello
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - nocopy parameter of -v start container failed" && ((ret++))

  isula run -ti --rm -v test:/usr:nocopy vol stat /usr/sbin
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - nocopy parameter of -v take no effect" && ((ret++))

  # test bind options
  isula run -tid --name vol11 --mount type=bind,source=/home,target=/aaa,bind-selinux-opts=z,bind-propagation=rprivate vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container vol11 failed" && ((ret++))

  # test volume copy
  isula run -ti --rm --mount target=/usr vol stat /usr/sbin
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test default copy failed" && ((ret++))

  isula run -tid --name vol12 -ti vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run vol12 failed" && ((ret++))

  isula exec -ti vol12 cat /vol/hello | grep world
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy regular failed" && ((ret++))

  isula exec -ti vol12 stat /vol/link | grep "Links: 2"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy hard link failed" && ((ret++))

  isula exec -ti vol12 readlink /vol/softlink | grep hello
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy soft link failed" && ((ret++))

  isula exec -ti vol12 stat /vol/dev | grep "character special file"
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy char device failed" && ((ret++))

  isula exec -ti vol12 stat /vol/dir/dir
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test volume copy recursive failed" && ((ret++))

  # test volume reuse
  isula run -tid -v reuse:/vol vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container for volume reuse failed" && ((ret++))

  isula run -tid -v reuse:/vol vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - reuse container volume failed" && ((ret++))

  # test volumes-from
  isula run -tid --name vol13 -v volumes_from:/volumes_from vol sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container for volumes-from failed" && ((ret++))

  isula run -tid --name vol14 --volumes-from vol13 busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with --volumes-from failed" && ((ret++))

  isula exec -ti vol14 stat /vol/dir/dir
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from anonymous volume failed" && ((ret++))

  isula exec -ti vol14 stat /volumes_from
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from named volume failed" && ((ret++))

  isula run -tid --name vol15 --volumes-from vol13:ro busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with --volumes-from readonly failed" && ((ret++))

  isula exec -ti vol15 touch /volumes_from/fail
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from readonly failed" && ((ret++))

  isula run -tid --name vol16 --volumes-from vol15 busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with --volumes-from readonly failed" && ((ret++))

  isula exec -ti vol16 touch /volumes_from/fail
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from default readonly failed" && ((ret++))

  isula run -tid --name vol17 --volumes-from vol15:rw busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with --volumes-from readonly failed" && ((ret++))

  isula exec -ti vol17 touch /volumes_from/fail
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - --volumes-from readwrite failed" && ((ret++))

  # test -v file with "/"
  touch /tmp/volume_test
  isula run -tid -v /tmp/volume_test/:/volume_test busybox sh
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test -v file with "/" failed" && ((ret++))

  # test invalid modes
  isula run -tid --rm -v aaa:/aaa:rslave busybox echo hello
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container -v with volume and propagation should fail" && ((ret++))

  isula run -tid --rm -v /home:/aaa:nocopy busybox echo hello
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container -v with bind and nocopy should fail" && ((ret++))

  isula run -tid --rm --mount src=aaa,dst=/aaa,bind-propagation=rslave busybox echo hello
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container --mount with volume and propagation should fail" && ((ret++))

  isula run -tid --rm --mount src=/home,dst=/aaa:nocopy busybox echo hello
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container --mount with bind and nocopy should fail" && ((ret++))

  # test clean up
  isula rm -f `isula ps -a -q`
  isula volume prune -f
  isula rmi vol
  num=`isula volume ls | wc -l`
  [[ $num -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - volume still exist after prune" && ((ret++))

  msg_info "${test} finished with return ${ret}..."
  return ${ret}
}

declare -i ans=0

test_volume || ((ans++))

show_result ${ans} "${curr_path}/${0}"
