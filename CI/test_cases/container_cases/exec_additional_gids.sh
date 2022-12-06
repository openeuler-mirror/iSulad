#!/bin/bash
#
# attributes: isulad exec check additional gids
# concurrent: YES
# spend time: 1

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description:CI
##- @Author: zhangxiaoyu
##- @Create: 2022-12-03
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh
test="exec additional gids test => test_exec_additional_gids"
test_log=$(mktemp /tmp/additional_gids_test_XXX)

USERNAME="user"
USER_UID="1000"
USER_GID="$USER_UID"
ADDITIONAL_GID="1001"
ADDITIONAL_GROUP="additional"

cont_name=add_gids_test
file_info="Keep it secret, keep it safe"

function additional_gids_test()
{
    local ret=0

    isula rm -f `isula ps -a -q`

    isula run -tid -n $cont_name ubuntu bash
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container" && ((ret++))

    isula exec $cont_name bash -c "groupadd --gid $USER_GID $USERNAME \
        && groupadd --gid $ADDITIONAL_GID $ADDITIONAL_GROUP \
        && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -G $ADDITIONAL_GROUP \
        && mkdir /app && chown ${USERNAME}:${USERNAME} /app \
        && echo $file_info > /app/sekrit.txt \
        && chown 0:${USER_GID} /app/sekrit.txt \
        && chmod 606 /app/sekrit.txt"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - create user and group failed" && ((ret++))

    /usr/bin/expect <<- EOF > ${test_log} 2>&1
set timeout 10
spawn isula exec -it --workdir /app -u $USERNAME $cont_name bash
expect "${USERNAME}*"
send "newgrp ${ADDITIONAL_GROUP}\n"
expect "*"
send "groups\n"
expect "$"
send "cat sekrit.txt\n"
expect "*"
send "exit\n"
expect "${USERNAME}*"
send "exit\n"
expect eof
EOF

    cat $test_log | grep "$file_info"
    [[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - read file success, but should fail" && ((ret++))

    cat $test_log | grep "Permission denied"
    [[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - read error message failed" && ((ret++))

    isula rm -f `isula ps -a -q`

    return ${ret}
}

declare -i ans=0

msg_info "${test} starting..."

additional_gids_test || ((ans++))

rm -rf ${test_log}

msg_info "${test} finished with return ${ret}..."

show_result ${ans} "${curr_path}/${0}"
