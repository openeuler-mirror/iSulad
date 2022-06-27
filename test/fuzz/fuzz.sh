#!/bin/bash
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
##- @Description: fuzz executive script
##- @Author: wangfengtu
##- @Create: 2022-06-29
#######################################################################

current_dir=$(cd $(dirname $0) && pwd)
isulad_src_path=$(pwd)/../../
testcases="$@"

if [ "$#" == "0" ];then
    testcases=(test_gr_obj_parser_fuzz test_pw_obj_parser_fuzz test_volume_mount_spec_fuzz test_volume_parse_volume_fuzz)
fi

find /usr -name "libclang_rt.fuzzer-$(uname -m)*"
if [ $? != 0 ];then
    echo "error: static shared library of fuzz not found"
    exit 1
fi

for testcase in ${testcases[@]}
do
    mkdir -p ${current_dir}/corpus

    # 运行fuzz测试程序
    fuzz_option="${current_dir}/corpus -dict=${current_dir}/dict/${testcase}.dict -runs=30000000 -max_total_time=10800"
    ${current_dir}/$testcase $fuzz_option -artifact_prefix=$testcase- > $isulad_src_path/$testcase.log 2>&1
    if [ $? != 0 ];then
        echo "execute fuzz $testcase failed"
        exit 1
    fi

    # 查找crash文件
    echo "############## Fuzz Result ###############"
    crash=`find -name "*-crash-*"`
    if [ x"${crash}" != x"" ];then
        echo "find bugs while fuzzing $testcase, pls check <*-crash-*> file"
        find -name "*-crash-*"
        exit 1
    else
        echo "fuzz $testcase success."
        rm -f ${current_dir}/corpus/*
    fi
done

echo "all fuzz success"
exit 0
