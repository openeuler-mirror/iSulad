#!/bin/bash
#
# attributes: cleanup container leftover
# concurrent: NA
declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

containerid=$(isula run -tid busybox ls)

check_valgrind_log
rm -rf "$LCR_ROOT_PATH/$containerid"

start_isulad_with_valgrind
wait_isulad_running

ret=0
ls "/var/lib/isulad/storage/overlay-containers/$containerid"
if [ $? != 0 ]; then
    echo "ls can't access which is expected"
    ret=0
else 
    ret=1; 
fi
check_valgrind_log
[[ $? -ne 0 ]] && msg_err "cleanup leftover - memory leak, please check...." && ((ret++))

show_result $ret "${curr_path}/${0}"
