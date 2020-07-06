#!/bin/bash

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

# 查找crash文件

echo "############## Fuzz Result ###############"
crash=`find -name "*-crash-*"`
if [ x"${crash}" != x"" ];then
    echo "find bugs while fuzzing, pls check <*-crash-*> file"
    find -name "*-crash-*"
    exit 1
else
    echo "all fuzz success."
fi
