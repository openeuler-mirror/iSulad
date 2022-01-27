#!/bin/bash
#
# attributes: isulad inheritance version
# concurrent: YES
# spend time: 1

#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
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

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
source ../helpers.sh

function isulad_version()
{
    cut_output_lines isulad --version
    fn_check_eq "$?" "0" "check failed"
    if ! [[ ${lines[0]} =~ Version\ [0-9]+\.[0-9]+\.[0-9]+,\ commit ]];then
        echo "isulad version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
}

function isula_version()
{
    cut_output_lines isula --version
    fn_check_eq "$?" "0" "check failed"
    if ![[ ${lines[0]} =~ Version\ [0-9]+\.[0-9]+\.[0-9]+,\ commit ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    cut_output_lines isula version
    fn_check_eq "$?" "0" "check failed"
    if [[ "${lines[0]}" != "Client:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[1]}" != "  Version:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[2]}" != "  Git commit:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[3]}" != "  Built:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    if [[ "${lines[4]}" != "Server:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[5]}" != "  Version:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[6]}" != "  Git commit:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[7]}" != "  Built:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    if [[ "${lines[8]}" != "OCI config:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[9]}" != "  Version:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[10]}" != "  Default file:"* ]];then
        echo "isula version error"
        TC_RET_T=$(($TC_RET_T+1))
    fi

    isula info
}

function do_test_t()
{
    isula_version
    isulad_version

    return $TC_RET_T
}

ret=0

do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic version"
