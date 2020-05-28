#!/bin/bash
#
# attributes: isulad inheritance import
# concurrent: YES
# spend time: 14

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
##- @Create: 2020-05-27
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ./helpers.bash

function import_tarball()
{
    tarball=$curr_path/busybox_rootfs.tar
    importname=imported_image
    containername=import_tarball
    isula run -tid --name $containername busybox
    fn_check_eq "$?" "0" "run container $containername failed"

    isula export -o $tarball $containername
    fn_check_eq "$?" "0" "export container $containername failed"

    isula import $tarball $importname
    fn_check_eq "$?" "0" "import $tarball to $importname failed"

    isula run --rm -ti $importname echo hello
    fn_check_eq "$?" "0" "run imported image failed"

    isula rmi $importname
    fn_check_eq "$?" "0" "rmi imported image failed"

    isula rm -f $containername
    fn_check_eq "$?" "0" "rm container $containername failed"

    rm -f $tarball
}

function do_test_t()
{
    import_tarball

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic import"
