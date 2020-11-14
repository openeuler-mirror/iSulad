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
VOLUME_FUZZ_OPTION="${current_dir}/corpus -dict=${current_dir}/dict/volume_fuzz.dict -runs=1000000 -max_total_time=3600"

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
${current_dir}/test_volume_mount_spec_fuzz ${VOLUME_FUZZ_OPTION} -artifact_prefix=test_volume_mount_spec_fuzz-
${current_dir}/test_volume_parse_volume_fuzz ${VOLUME_FUZZ_OPTION} -artifact_prefix=test_volume_parse_volume_fuzz-

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

if [ x"$1" == x"gcov" ];then
    umask 0022
    export GCOV_RESULT_PATH=/tmp/isulad-fuzz-gcov
    ISULAD_SRC_PATH=$(pwd)/../../

    echo "================================Generate isulad fuzz GCOV data===================================="
    cd ${ISULAD_SRC_PATH}/build
    lcov --directory . --capture --output-file coverage.info
    # Remove std/build files
    lcov --remove coverage.info '/usr/*' -o coverage.info
    lcov --remove coverage.info 'build/*' -o coverage.info
    lcov --remove coverage.info 'test/*' -o coverage.info

    # Generate html
    genhtml --ignore-errors source -o $GCOV_RESULT_PATH/coverage coverage.info

    tar -zcf $ISULAD_SRC_PATH/isulad-gcov.tar.gz $GCOV_RESULT_PATH

    echo "================================Generate isulad fuzz GCOV finish===================================="
fi
