#!/bin/bash
#
# attributes: isulad inheritance version
# concurrent: YES
# spend time: 1

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
##- @Create: 2020-05-04
#######################################################################

curr_path=$(dirname $(readlink -f "$0"))
data_path=$(realpath $curr_path/../data)
driver="overlay2"
source ./helpers.bash

function pre_test()
{
    cut_output_lines isula info
    fn_check_eq "$?" "0" "check failed"
    
    for i in ${lines[@]};do
	    echo $i | grep 'devicemapper'
	    if [ $? -eq 0 ]; then
		    driver="devicemapper"
	    fi
    done

}

function overlay2_status()
{
    if [[ "${lines[6]}" != "Storage Driver:"* ]];then
        echo "isula info error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[7]}" != " Backing Filesystem:"* ]];then
        echo "isula info error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
    if [[ "${lines[8]}" != " Supports d_type:"* ]];then
        echo "isula info error"
        TC_RET_T=$(($TC_RET_T+1))
    fi
}

function devicemapper_status()
{
	echo "TODO"
}

function do_test_t()
{
    pre_test
    if [[ "$driver"x = "overlay2"x ]];then
	    overlay2_status
    elif [[ "driver"x = "devicemapper"x ]];then
	    devicemapper_status
    else
	    echo "error: not support $driver"
	    TC_RET_T=$(($TC_RET_T+1))
    fi

    return $TC_RET_T

}

ret=0
do_test_t
if [ $? -ne 0 ];then
    let "ret=$ret + 1"
fi

show_result $ret "basic storage driver status"
