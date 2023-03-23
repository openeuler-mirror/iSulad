#!/bin/bash
#
# attributes: cleanup container leftover
# concurrent: NA
declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function test_cleanup()
{
    local runtime=$1
    local test="cleanup_test => (${runtime})"
    msg_info "${test} starting..."

    containerid=$(isula run -tid --runtime $runtime busybox ls)

    check_valgrind_log
    rm -rf "$RUNTIME_ROOT_PATH/$runtime/$containerid"

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

    start_isulad_with_valgrind
    wait_isulad_running
    msg_info "${test} finished with return ${ret}..."
}

declare -i ret=0

for element in ${RUNTIME_LIST[@]};
do
    test_cleanup $element || ((ret++))
done

show_result $ret "${curr_path}/${0}"