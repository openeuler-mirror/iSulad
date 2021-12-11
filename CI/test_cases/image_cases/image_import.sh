#!/bin/bash
#
# attributes: isulad basic image
# concurrent: NA
# spend time: 4

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
##- @Create: 2020-06-19
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
rootfs_tar="${curr_path}/rootfs.tar"
rootfs_tar_xz="${curr_path}/rootfs.tar.xz"
rootfs_empty_gz="${curr_path}/empty.gz"
rootfs_file_gz="${curr_path}/file.gz"
import_empty_gz="empty"
import_file_gz="file"
import_tar="import_tar"
import_tar_xz="import_tar_xz"

function test_image_import() {
    local ret=0
    local test="isula import image test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula import "$rootfs_tar" ${import_tar}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - import image failed: ${rootfs_tar}" && ((ret++))

    isula import "$rootfs_tar_xz" ${import_tar_xz}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - import image failed: ${rootfs_tar_xz}" && ((ret++))

    isula run --rm -ti ${import_tar} echo hello
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to run ${import_tar}" && ((ret++))

    isula run --rm -ti ${import_tar_xz} echo hello
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to run ${import_tar_xz}" && ((ret++))

    isula rm -f $(isula ps -a -q)

    isula rmi ${import_tar}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to remove ${import_tar}" && ((ret++))

    isula rmi ${import_tar_xz}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - fail to remove ${import_tar_xz}" && ((ret++))

    isula import "${rootfs_empty_gz}" ${import_empty_gz}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - should not import ${rootfs_empty_gz} success" && ((ret++))

    isula import "${rootfs_file_gz}" ${import_file_gz}
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - should not import ${rootfs_file_gz} success" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

declare -i ans=0

test_image_import || ((ans++))
if [ "${ans}" -ne 0 ]; then
    cat "$ISUALD_LOG"
fi

show_result "${ans}" "${curr_path}/${0}"
