#!/bin/bash
#
# attributes: isulad basic image
# concurrent: NA
# spend time: 20

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.bash

do_test_t()
{
  echo "test begin"

  isula pull busybox
  if [ $? -ne 0 ]; then
    echo "failed pull image"
    TC_RET_T=$(($TC_RET_T+1))
  fi

  isula images | grep busybox
  if [ $? -ne 0 ]; then
    echo "missing list image busybox"
    TC_RET_T=$(($TC_RET_T+1))
  fi

  isula rmi busybox
  if [ $? -ne 0 ]; then
    echo "Failed to remove image busybox"
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

show_result $ret "images_remove.bash"
