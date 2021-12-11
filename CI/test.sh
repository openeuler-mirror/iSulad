#! /bin/bash
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
##- @Create: 2020-03-30
#######################################################################
set +e
subcmd="$1"
testcase="$2"
logfile="$3"
resultpass=/tmp/ciresult.0
resultfail=/tmp/ciresult.1
umask 0022

if [ "$subcmd" == "run" ]; then
    rm -rf $resultfail $resultpass "$logfile"
    $testcase > "$logfile" 2>&1
    if [ $? -eq 0 ]; then
        touch $resultpass
    else
        touch $resultfail
    fi
elif [ "$subcmd" == "get" ]; then
    set +x
    while true; do
        if [ -e $resultfail ]; then
            exit 1
        fi
        if [ -e $resultpass ]; then
            exit 0
        fi
        sleep 2
    done
else
    echo "unknown subcmd $subcmd"
    exit 1
fi
