#!/bin/bash
#
# attributes: isulad basic container hook
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
##- @Author: gaohuatao
##- @Create: 2020-06-03
#######################################################################

declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh
opt_size_basesize=10
opt_size_lower=9
opt_size_upper=11

function test_devmapper_size() {
    local ret=0
    local image="busybox"
    local test="container top test => (${FUNCNAME[@]})"

    msg_info "${test} starting..."

    isula pull ${image}
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return "${FAILURE}"

    isula images | grep busybox
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

    cont_base=$(isula run -itd --storage-opt size="${opt_size_basesize}G" $image /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with storage-opt size:${opt_size_basesize}G" && ((ret++))

    cont_lower=$(isula run -itd --storage-opt size="${opt_size_lower}G" $image /bin/sh)
    [[ $nret -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - run container with storage-opt size: ${opt_size_lower}G that not expected as failed" && ((ret++))

    cont_upper=$(isula run -itd --storage-opt size="${opt_size_upper}G" $image /bin/sh)
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with storage-opt size:${opt_size_upper}G" && ((ret++))

    isula rm -f "$cont_base"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container with storage-opt size: ${opt_size_basesize}G" && ((ret++))

    isula rm -f "$cont_upper"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container with storage-opt size: ${cont_upper}G" && ((ret++))

    msg_info "${test} finished with return ${ret}..."
    return "${ret}"
}

declare -i ans=0
storage_driver=$(isula info | grep "Storage Driver" | cut -d ':' -f 2)
if [[ $storage_driver == "devicemapper" ]]; then
    test_devmapper_size || ((ans++))
fi

show_result "${ans}" "${curr_path}/${0}"
