#!/bin/bash
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
##- @Description: generate gcov
##- @Author: WuJing
##- @Create: 2020-06-05
#######################################################################

set +e
set -x

umask 0022
export GCOV_RESULT_PATH=/tmp/isulad-gcov
ISULAD_SRC_PATH=$(env | grep TOPDIR | awk -F = '{print $2}')
export ISULAD_COPY_PATH=~/iSulad

echo "================================Generate GCOV data===================================="

echo "*****************Get iSulad GCOV data**************************"
cp -r ~/build $ISULAD_COPY_PATH
cd $ISULAD_COPY_PATH/build
ctest
lcov --directory . --capture --output-file coverage.info
# Remove std/build files
lcov --remove coverage.info '/usr/*' -o coverage.info
lcov --remove coverage.info 'build/*' -o coverage.info
lcov --remove coverage.info 'test/*' -o coverage.info

# Generate html
genhtml --ignore-errors source -o $GCOV_RESULT_PATH/coverage coverage.info

tar -zcf $ISULAD_SRC_PATH/isulad-gcov.tar.gz $GCOV_RESULT_PATH

echo "================================Generate GCOV finish===================================="
