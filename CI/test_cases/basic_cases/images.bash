#!/bin/bash
#
# attributes: isulad basic image
# concurrent: NA
# spend time: 2

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ./helpers.bash

INVALID_IMAGE="k~k"

do_test_t()
{
  echo "test begin"

  isula pull busybox
  if [ $? -ne 0 ]; then
    echo "failed pull image"
    TC_RET_T=$(($TC_RET_T+1))
  fi

  isula pull $INVALID_IMAGE
  if [ $? -eq 0 ];then
    echo "pull invalid image success"
    TC_RET_T=$(($TC_RET_T+1))
  fi

  isula images | grep busybox
  if [ $? -ne 0 ]; then
    echo "missing list image busybox"
    TC_RET_T=$(($TC_RET_T+1))
  fi

  isula inspect --format='{{json .image.loaded}}' busybox
  if [ $? -ne 0 ]; then
    echo "Failed to inspect image busybox loaded time"
    TC_RET_T=$(($TC_RET_T+1))
  fi

  isula inspect busybox | grep busybox
  if [ $? -ne 0 ]; then
    echo "Failed to inspect image busybox"
    TC_RET_T=$(($TC_RET_T+1))
  fi

  echo "test end"
  return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
  let "ret=$ret + 1"
fi

show_result $ret "images.bash"
