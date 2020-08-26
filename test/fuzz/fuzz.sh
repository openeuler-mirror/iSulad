#!/bin/bash
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
##- @Description: fuzz test executive script
##- @Author: jikui
##- @Create: 2020-07-09
#######################################################################

current_dir=$(cd $(dirname $0) && pwd)
FUZZ_OPTION="${current_dir}/corpus -dict=${current_dir}/dict/im_oci_image_exist_fuzz.dict -runs=1000000 -max_total_time=3600"

find /usr -name "libclang_rt.fuzzer-$(uname -m)*"
if [ $? != 0 ];then
    echo "error: static shared library of fuzz not found"
    exit 1
fi

if [ ! -d ${current_dir}/corpus ];then
    mkdir ${current_dir}/corpus
fi

# 运行fuzz测试程序
${current_dir}/im_oci_image_exist_fuzz ${FUZZ_OPTION} -artifact_prefix=im_oci_image_exist_fuzz-
${current_dir}/im_config_image_exist_fuzz ${FUZZ_OPTION} -artifact_prefix=im_config_image_exist_fuzz-
${current_dir}/im_get_image_count_fuzz ${FUZZ_OPTION} -artifact_prefix=im_get_image_count_fuzz-

# 查找crash文件

echo "############## Fuzz Result ###############"
crash=`find -name "*-crash-*"`
if [ x"${crash}" != x"" ];then
    echo "find bugs while fuzzing, pls check <*-crash-*> file"
    find -name "*-crash-*"
    exit 1
else
    echo "all fuzz success."
    rm -f ${current_dir}/corpus/*
    rm -f ${current_dir}/*_fuzz
fi
