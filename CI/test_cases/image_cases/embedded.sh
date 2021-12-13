#!/bin/bash
#
# attributes: isulad embedded image
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
##- @Create: 2021-02-20
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
test="embedded image test => test_embedded"

free_loop=""
embedded_basedir="$(pwd)/embedded/img"
embedded_basedir2="$(pwd)/embedded/img2"
embedded_basedir3="$(pwd)/embedded/img3"
embedded_basedir4="$(pwd)/embedded/img4"
embedded_basedir5="$(pwd)/embedded/img5"
embedded_manifest="$embedded_basedir/test.manifest"
embedded_manifest2="$embedded_basedir2/test.manifest"
embedded_manifest3="$embedded_basedir3/manifest"
embedded_manifest_template="$embedded_basedir/template.manifest"
embedded_manifest_invalid="$embedded_basedir/invalid.manifest"
embedded_manifest_invalid_sgn="$embedded_basedir/invalid.sgn"
embedded_manifest_not_file="$embedded_basedir/notfile"
embedded_manifest_not_exist="$embedded_basedir/notexist.manifest"
embedded_manifest_sgn2="$embedded_basedir2/test.sgn"
embedded_manifest_sgn5="$embedded_basedir5/sgn"
embedded_app="$embedded_basedir/app.img"
embedded_app2="$embedded_basedir2/app.img"
embedded_platform="$embedded_basedir/platform.img"
embedded_platform2="$embedded_basedir2/platform.img"
embedded_rootfs0="/tmp/embedded_rootfs0"
embedded_manifest_ori="$embedded_basedir/test.manifest.ori"
embedded_manifest_template_ori="$embedded_basedir/template.manifest.ori"

function test_load_image()
{
  local ret=0

  isula load -i "$embedded_manifest" -t abc
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load invalid type failed" && ((ret++))

  # load embedded image
  isula load -i "$embedded_manifest" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load embedded image failed" && ((ret++))

  # load embedded image again
  isula load -i "$embedded_manifest" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load embedded image again failed" && ((ret++))

  # delete embedded image
  isula rmi test:v1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - delete embedded image failed" && ((ret++))

  # load embedded image again
  isula load -i "$embedded_manifest" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load embedded image again failed" && ((ret++))

  # delete embedded image
  isula rmi test:v1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - delete embedded image failed" && ((ret++))

  return ${ret}
}

function test_run_image()
{
  local ret=0

  isula run -t -n embedded_test1 nonexistentname1:v1 /bin/sh
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run nonexistent image should failed" && ((ret++))

  isula load -i "$embedded_manifest" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load embedded image failed" && ((ret++))

  # run container based on embedded image
  isula run --name embedded_test1 test:v1 ls /home/home/home
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run embedded image failed" && ((ret++))

  # delete container based on embedded image
  isula rm embedded_test1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - delete container based on embedded image failed" && ((ret++))

  # test image's env
  isula run --name embedded_test1 test:v1 /bin/sh -c "echo \$c | grep \"d e\""
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test image's env failed" && ((ret++))

  # delete container based on embedded image
  isula rm embedded_test1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - delete container based on embedded image failed" && ((ret++))

  # delete embedded image
  isula rmi test:v1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - delete embedded image failed" && ((ret++))

  return ${ret}
}

function test_mount()
{
  local ret=0

  # load embedded image
  isula load -i "$embedded_manifest" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load embedded imagefailed" && ((ret++))

  # run --mount
  isula run --mount type=bind,src="$embedded_basedir",dst=/usr,ro=true,bind-propagation=rprivate --name embedded_test2 test:v1 true
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run --mount failed" && ((ret++))

  testcontainer embedded_test2 exited

  isula rm embedded_test2

  # test invalid mode
  isula run --mount type=bind,src="$embedded_basedir",dst=/usr,ro=invalid --name embedded_test2 test:v1 true
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid mode should failed" && ((ret++))

  isula rm embedded_test2

  # test invalid bind propagation mode
  isula run --mount type=bind,src="$embedded_basedir",dst=/usr,bind-propagation=invalid --name embedded_test2 test:v1 true
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid bind propagation mode should failed" && ((ret++))

  isula rm embedded_test2

  # test source not exist
  isula run --mount type=bind,src=abcdefg/notexist,dst=/usr --name embedded_test2 test:v1 true
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - invalid source not exist should failed" && ((ret++))

  isula rm embedded_test2

  # test source not a regular file
  isula run --mount type=squashfs,src=/tmp,dst=/usr --name embedded_test2 test:v1 true
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - source not a regular file should failed" && ((ret++))

  isula rm embedded_test2

  # test path //tmp/test
  mkdir -p /tmp/test_mount
  mkdir -p /tmp/test_mount1/test
  isula run -v /tmp/test_mount:/tmp --mount type=bind,src=/tmp/test_mount1,dst=//tmp/test_mount1,ro=true,bind-propagation=rprivate --name embedded_test2 test:v1 ls /tmp/test_mount1/test
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test path //tmp/test failed" && ((ret++))

  isula rm embedded_test2

  # delete embedded image
  isula rmi test:v1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - delete embedded image failed" && ((ret++))

  return ${ret}
}

function test_query_image()
{
  local ret=0

  # load embedded image
  isula load -i "$embedded_manifest" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load embedded imagefailed" && ((ret++))

  # inspect embedded image
  isula inspect test:v1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect embedded image failed" && ((ret++))

  # test list embedded image
  isula images | grep test | grep v1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - list embedded image failed" && ((ret++))

  # inspect nonexist item
  isula inspect -f '{{json .abc}}' test:v1
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect nonexist item should failed" && ((ret++))

  # test inspect container, it should conatainer image info
  isula run --name embedded_inspect test:v1 ls /home/home/home
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container for inspect failed" && ((ret++))

  isula inspect -f '{{json .Image}}' embedded_inspect
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - image does not contain image info failed" && ((ret++))

  # test list container based on embedded image
  isula ps -a | grep embedded_inspect
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ps does not contain embedded container failed" && ((ret++))

  # delete container
  isula rm embedded_inspect
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - delete container for inspect failed" && ((ret++))

  # delete embedded image
  isula rmi test:v1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - delete embedded image failed" && ((ret++))

  # test inspect nonexist image
  isula inspect test:v1
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - inspect nonexist image should failed" && ((ret++))

  # test list nonexist image
  isula images | grep test | grep v1
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - list nonexist image should failed" && ((ret++))

  # test list nonexist container
  isula ps -a | grep embedded_inspect
  [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - ps should not contain embedded container failed" && ((ret++))

  return ${ret}
}

function test_invalid_manifest_part1()
{
  local ret=0

  # test 'none' image name
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/test:v1/none/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test 'none' image name failed" && ((ret++))

  # test 'none:latest' image name
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/test:v1/none:latest/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test 'none:latest' image name failed" && ((ret++))

  # test invalid image name k~k
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/test:v1/k~k/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid image name k~k failed" && ((ret++))

  # test invalid image name test
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/test:v1/test/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid image name test failed" && ((ret++))

  # test invalid time
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/Z/Zabc#$@/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid image time failed" && ((ret++))

  # test invalid layer number
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "16,36d" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid layer number failed" && ((ret++))

  # test layer 0 not a device
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s#$free_loop#/home#g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test layer 0 not a device failed" && ((ret++))

  # test layer(not the first layer) not a regular file
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  mkdir -p "$embedded_manifest_not_file"
  sed -i "s#platform.img#notfile#g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test layer(not the first layer) not a regular file failed" && ((ret++))
  rm -rf "$embedded_manifest_not_file"

  # test invalid layer digest
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/4613a9d1e9016293f53833b0ac61ea072882d468fe2fce7701ecea6f201eebbe/7a7eb18fd0a7b9ac0cdae8c9754ff846d65a4831b9ad8786d943618b497bd886/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid layer digest failed" && ((ret++))

  # test invalid layer not exist
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/app.img/kkk/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid layer not exist failed" && ((ret++))

  # test invalid host path(not relative path)
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s#platform.img#/platform.img#g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid host path(not relative path) failed" && ((ret++))

  # test invalid container path(not absolute path)
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s#/home/home#home/home#g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid container path(not absolute path) failed" && ((ret++))

  # test invalid first layer(not absolute path)
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s#$free_loop#${free_loop:1}#g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid first layer(not absolute path) failed" && ((ret++))

  # test invalid manifest digest
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  echo -n "sha256:36c7c17757c24fa1e86018c8009f3b98690709236f05910937d59e401d87d6c5" > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid manifest digest failed" && ((ret++))

  # test invalid manifest not exist
  isula load -i "$embedded_manifest_not_exist" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid manifest not exist failed" && ((ret++))

  # test invalid manifest not a regular file
  isula load -i /dev/zero -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid manifest not a regular file failed" && ((ret++))

  # test invalid manifest empty file
  rm -f "$embedded_manifest_invalid"
  touch "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid manifest empty file failed" && ((ret++))

  # test invalid manifest not a json file
  rm -f "$embedded_manifest_invalid"
  echo hello > "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid manifest not a json file failed" && ((ret++))

  # test image conflict when in different path
  rm -rf "$embedded_basedir2"
  cp -rf "$embedded_basedir" "$embedded_basedir2"
  isula load -i "$embedded_manifest" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test image conflict when in different path failed" && ((ret++))

  echo -n sha256:$(sha256sum "$embedded_manifest2" | awk '{print $1}') > "$embedded_manifest_sgn2"
  isula load -i "$embedded_manifest2" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load manifest in different path should failed" && ((ret++))

  rm -rf "$embedded_basedir2"
  isula rmi test:v1

  return ${ret}
}

function test_invalid_manifest_part2()
{
  local ret=0

  # test manifest's sgn file not exist
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  rm -f "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test manifest's sgn file not exist failed" && ((ret++))

  # test content of manifest's sgn file not right
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  # note: add '\n' at the end of the sgn file
  echo sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test content of manifest's sgn file not right failed" && ((ret++))

  # test invalid schema version
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "2d" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid schema version failed" && ((ret++))

  # test invalid manifest's media type
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/embedded/invalid/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid manifest's media type failed" && ((ret++))

  # test invalid manifest's layer type
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/squashfs/invalid/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test invalid manifest's layer type failed" && ((ret++))

  # test size negative number
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "s/823/-823/g" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test size negative number failed" && ((ret++))

  # test first layer digest not empty
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "19d" "$embedded_manifest_invalid"
  sed -i "19i\"digest\": \"a\"," "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test size negative number failed" && ((ret++))

  # test first layer path in container not empty
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "21d" "$embedded_manifest_invalid"
  sed -i "21i\"pathInContainer\": \"a\"" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 1 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test first layer path in container not empty failed" && ((ret++))

  return ${ret}
}

function test_entrypoint()
{
  local ret=0

  # load embedded image
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "12i\"/bin/ls\"," "$embedded_manifest_invalid"
  sed -i "13i\"/home\"" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load embedded image failed" && ((ret++))

  # test image's entrypoint
  isula run --name embedded_entrypoint1 test:v1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test image's entrypoint failed" && ((ret++))

  isula rm embedded_entrypoint1

  # test image's entrypoint with cmds
  isula run --name embedded_entrypoint1 test:v1 /bin
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test image's entrypoint with cmds failed" && ((ret++))

  isula rm embedded_entrypoint1

  # test image's entrypoint override image's entrypoint
  isula run --entrypoint=/bin/ls --name embedded_entrypoint1 test:v1 /bin
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test image's entrypoint override image's entrypoint failed" && ((ret++))

  isula rm embedded_entrypoint1
  isula rmi test:v1

  # test entrypoint with variable
  cp -f "$embedded_manifest_template" "$embedded_manifest_invalid"
  sed -i "12i\"/bin/sh\"," "$embedded_manifest_invalid"
  sed -i "13i\"-c\"," "$embedded_manifest_invalid"
  sed -i "14i\"ls /ho\${env_id}\"" "$embedded_manifest_invalid"
  echo -n sha256:$(sha256sum "$embedded_manifest_invalid" | awk '{print $1}') > "$embedded_manifest_invalid_sgn"
  isula load -i "$embedded_manifest_invalid" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test entrypoint with variable failed" && ((ret++))

  isula run -e env_id=me --name embedded_entrypoint1 test:v1
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - test run embedded image with env failed" && ((ret++))

  isula rm embedded_entrypoint1
  isula rmi test:v1

  return ${ret}
}

function test_symbolic()
{
  local ret=0

  # test symbolic
  # image layout
  # .
  # |__ img
  # |   |__ app.img
  # |   |__ platform.img
  # |
  # |__ img2
  # |   |__ app.img -> ../img/app.img
  # |   |__ platform.img -> ../img/platform.img
  # |   |__ test.manifest
  # |   |__ test.sgn -> ../img5/sgn
  # |
  # |__ img3
  # |   |__ manifest -> ../img2/test.manifest
  # |
  # |__ img4 -> img3
  # |
  # |__ img5
  #     |__ sgn
  #
  # /tmp/embedded_rootfs0 -> /dev/loopx

  rm -rf "$embedded_basedir2"
  mkdir -p "$embedded_basedir2"
  ln -sf "$embedded_app" "$embedded_app2"
  ln -sf "$embedded_platform" "$embedded_platform2"
  cp -f "$embedded_manifest_template" "$embedded_manifest2"
  sed -i "s#$free_loop#$embedded_rootfs0#g" "$embedded_manifest2"
  ln -sf $free_loop $embedded_rootfs0
  mkdir -p "$embedded_basedir5"
  echo -n sha256:$(sha256sum "$embedded_manifest2" | awk '{print $1}') > "$embedded_manifest_sgn5"
  ln -sf "$embedded_manifest_sgn5" "$embedded_manifest_sgn2"
  mkdir -p "$embedded_basedir3"
  ln -sf "$embedded_manifest2" "$embedded_manifest3"
  ln -sf "$embedded_basedir3" "$embedded_basedir4"

  # load embedded image
  isula load -i "$embedded_manifest2" -t embedded
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - load embedded image failed" && ((ret++))

  # run container based on embedded image
  isula run --name embedded_test_symbolic test:v1 ls /home/home/home
  [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container based on embedded image failed" && ((ret++))

  isula rm embedded_test_symbolic
  isula rmi test:v1

  return ${ret}
}

function prepare_test_embedded()
{
  local ret=0

  isula rm -f `isula ps -a -q`
  isula rmi test:v1

  free_loop=$(losetup -f)
  losetup $free_loop $embedded_basedir/busybox.img

  cp -f $embedded_manifest_ori $embedded_manifest
  cp -f $embedded_manifest_template_ori $embedded_manifest_template
  sed -i "s#/dev/ram0#$free_loop#g" "$embedded_manifest"
  sed -i "s#/dev/ram0#$free_loop#g" "$embedded_manifest_template"
  checksum=$(sha256sum $embedded_basedir/test.manifest | awk '{print $1}')
  echo -n "sha256:$checksum" > $embedded_basedir/test.sgn

  return ${ret}
}

function post_test_embedded()
{
  local ret=0

  rm -rf "$embedded_manifest_not_file"
  rm -rf "$embedded_basedir2"
  rm -rf "$embedded_basedir3"
  rm -rf "$embedded_basedir4"
  rm -rf "$embedded_basedir5"

  isula rm -f `isula ps -a -q`
  isula rmi test:v1

  umount $(mount | grep busybox.img | awk '{print $3}')
  losetup -d $free_loop

  return ${ret}
}

declare -i ans=0

msg_info "${test} starting..."
[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - start isulad failed" && ((ret++))

prepare_test_embedded || ((ans++))

test_load_image || ((ans++))
test_run_image || ((ans++))
test_mount || ((ans++))
test_query_image || ((ans++))
test_invalid_manifest_part1 || ((ans++))
test_invalid_manifest_part2 || ((ans++))
test_entrypoint || ((ans++))
test_symbolic || ((ans++))

post_test_embedded

msg_info "${test} finished with return ${ans}..."

show_result ${ans} "${curr_path}/${0}"
