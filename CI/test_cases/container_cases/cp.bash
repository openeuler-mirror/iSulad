#!/bin/bash
#
# attributes: isulad basic container hook
# concurrent: NA
# spend time: 8

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
##- @Author: lifeng
##- @Create: 2020-06-03
#######################################################################
declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.bash

cpfiles=/tmp/subcmdcp

test_cp_file_from_container()
{
    local ret=0
    containername=$1
    # cp from container
    dstfile=$cpfiles/passwd
    rm -rf $dstfile
    cd $cpfiles

    isula cp nonexists:etc . 2>&1 | grep "No such container"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check noexists output" && ((ret++))

    isula cp nonexists:etc $containername:$cpfiles 2>&1 | grep "copying between containers is not supported"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to check copying between containers output" && ((ret++))

    isula cp $containername:etc/passwd .
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    if [ ! -f $dstfile ];then
        msg_err "${FUNCNAME[0]}:${LINENO} - failed to check dstfile" && ((ret++))
    fi

    rm -rf $dstfile

    dstfile=$cpfiles/passwd_renamed
    rm -rf $dstfile
    isula cp $containername:../etc/passwd passwd_renamed
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    if [ ! -f $dstfile ];then
        msg_err "${FUNCNAME[0]}:${LINENO} - failed to check dstfile" && ((ret++))
    fi
    rm -rf $dstfile

    isula cp $containername:/etc/../etc/passwd/ $cpfiles 2>&1 | grep "Not a directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp $containername:/etc/nonexists $cpfiles 2>&1 | grep "No such file or directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    dstfile=$cpfiles/etc
    rm -rf $dstfile
    touch $dstfile
    isula cp $containername:/etc $dstfile 2>&1 | grep "cannot copy directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))
    rm -rf $dstfile

    isula cp $containername:/etc/passwd $cpfiles/nonexists/ 2>&1 | grep "no such directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    return ${ret}
}

test_cp_dir_from_container()
{
    local ret=0
    containername=$1
    # cp from container
    dstfile=$cpfiles/etc
    rm -rf $dstfile
    cd $cpfiles
    isula cp $containername:etc .
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))
    if [ ! -d $dstfile ];then
        msg_err "${FUNCNAME[0]}:${LINENO} - failed to check dstfile" && ((ret++))
    fi
    rm -rf $dstfile

    dstfile=$cpfiles/etc_renamed
    rm -rf $dstfile
    isula cp $containername:../etc etc_renamed
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))
    if [ ! -d $dstfile ];then
        msg_err "${FUNCNAME[0]}:${LINENO} - failed to check dstfile" && ((ret++))
    fi
    rm -rf $dstfile

    dstfile=$cpfiles/etcfiles
    rm -rf $dstfile
    mkdir -p $dstfile
    isula cp $containername:/etc/. etcfiles
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))
    if [ ! -f $dstfile/passwd ];then
        msg_err "${FUNCNAME[0]}:${LINENO} - failed to check dstfile" && ((ret++))
    fi
    rm -rf $dstfile

    return ${ret}
}

test_cp_file_to_container()
{
    local ret=0
    containername=$1
    # cp from container
    dstfile=$cpfiles/passwd
    cd /etc

    isula cp passwd nonexists:$dstfile 2>&1 | grep "No such container"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp passwd $containername:./$cpfiles
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula exec $containername /bin/sh -c "ls $dstfile"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    dstfile=$cpfiles/passwd_renamed
    isula cp ../../../etc/passwd $containername:../$dstfile
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula exec $containername /bin/sh -c "ls $dstfile"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp ./passwd $containername:/etc/passwd/  2>&1 | grep "no such directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp /etc/../etc/passwd $containername:/etc/passwd/nonexists  2>&1 | grep "extraction point is not a directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp /etc/passwd $containername:$cpfiles/nonexists/ 2>&1 | grep "no such directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp /etc/passwd $containername:$cpfiles/nonexists/nonexists 2>&1 | grep "No such file or directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp /etc/nonexists $containername:$cpfiles 2>&1 | grep "No such file or directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))
    rm -rf $dstfile

    dstfile=$cpfiles/etc
    isula exec $containername /bin/sh -c "rm -rf $dstfile; touch $dstfile"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp /etc $containername:$dstfile 2>&1 | grep "cannot copy directory"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    return ${ret}
}

test_cp_dir_to_container()
{
    local ret=0
    containername=$1
    # cp from container
    dstfile=$cpfiles/etc
    cd /
    isula cp .././etc $containername:$cpfiles
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula exec $containername /bin/sh -c "ls $dstfile"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    dstfile=$cpfiles/etc_renamed
    isula cp ./etc $containername:$dstfile
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula exec $containername /bin/sh -c "ls $dstfile"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    dstfile=$cpfiles/etcfiles
    cd /etc
    isula exec $containername /bin/sh -c "rm -rf $dstfile; mkdir -p $dstfile"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp . $containername:$dstfile
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula exec $containername /bin/sh -c "ls $dstfile/passwd"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    return ${ret}
}

test_cp_symlink_to_container()
{
    local ret=0
    containername=$1
    cd /tmp
    rm -rf l1
    ln -s ../..$cpfiles/linkto l1
    isula cp l1 $containername:$cpfiles
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula exec $containername ls -al $cpfiles | grep "l1.*../..$cpfiles/linkto"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp l1 $containername:$cpfiles/l1
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula exec $containername ls -al $cpfiles | grep "linkto.*../..$cpfiles/linkto"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    rm -rf l1

    isula exec $containername /bin/sh -c "cd $cpfiles; rm -rf t1 t2 target; ln -s ./t1 t2; ln -s target t1"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp /etc/passwd $containername:$cpfiles/t2
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula exec $containername /bin/sh -c "cat $cpfiles/target | grep root"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    return ${ret}
}

test_cp_symlink_from_container()
{
    local ret=0
    containername=$1
    cd $cpfiles
    rm -rf l1 l2
    isula exec $containername /bin/sh -c "cd $cpfiles; rm -rf l1 l2 target; touch target; ln -s target l1; ln -s l1 l2"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    isula cp $containername:$cpfiles/l1 .
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    ls -al . | grep "l1.*target"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to do copy" && ((ret++))

    return ${ret}
}

function cp_test_t()
{
    local ret=0
    local image="busybox"
    local test="container cp test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    containername=test_cmd_cp
	isula run -n $containername -itd $image
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container: ${image}" && ((ret++))

    rm -rf $cpfiles
    mkdir -p $cpfiles
    isula exec $containername mkdir -p $cpfiles
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to exec container: ${containername}" && ((ret++))

    test_cp_file_from_container $containername || ((ret++))
    test_cp_dir_from_container $containername || ((ret++))
    test_cp_file_to_container $containername || ((ret++))
    test_cp_symlink_to_container $containername || ((ret++))
    test_cp_symlink_from_container $containername || ((ret++))

    isula rm -f $containername
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container: ${containername}" && ((ret++))

    rm -rf $cpfiles
    echo "test end"
    return ${ret}
}

declare -i ans=0

cp_test_t || ((ans++))

show_result ${ans} "${curr_path}/${0}"
