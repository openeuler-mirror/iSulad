#!/bin/bash
set +e
set -x

umask 0022
export GCOV_RESULT_PATH=/tmp/isulad-gcov
ISULAD_SRC_PATH=$(env | grep TOPDIR | awk -F = '{print $2}')
export ISULAD_COPY_PATH=~/iSulad

echo "================================Generate GCOV data===================================="

echo "*****************Get iSulad GCOV data**************************"
cp -r ~/build $ISULAD_COPY_PATH
cd $ISULAD_COPY_PATH/build/src/CMakeFiles
lcov -c -o isulad.info -d isulad.dir
lcov -c -o isula.info -d isula.dir/src
lcov -c -o isulad-shim.info -d isulad-shim.dir/src
lcov -c -o libisula.info -d libisula.dir

# Remove std files
lcov --remove isulad.info '/usr/*' -o isulad.info
lcov --remove isula.info '/usr/*' -o isula.info
lcov --remove isulad-shim.info '/usr/*' -o isulad-shim.info
lcov --remove libisula.info '/usr/*' -o libisula.info

# Generate html
genhtml --ignore-errors source -o $GCOV_RESULT_PATH/isulad isulad.info
genhtml --ignore-errors source -o $GCOV_RESULT_PATH/isula isula.info
genhtml --ignore-errors source -o $GCOV_RESULT_PATH/isulad-shim isulad-shim.info
genhtml --ignore-errors source -o $GCOV_RESULT_PATH/libisula libisula.info

cd $ISULAD_COPY_PATH/build/src/http/CMakeFiles
lcov -c -o libhttpclient.info '/usr/*' -o libhttpclient.info

# Remove std file
lcov --remove libhttpclient.info '/usr/*' -o libhttpclient.info

# Generate html
genhtml --ignore-errors source -o $GCOV_RESULT_PATH/libhttpclient libhttpclient.info

tar -zcf $ISULAD_SRC_PATH/isulad-gcov.tar.gz $GCOV_RESULT_PATH

echo "================================Generate GCOV finish===================================="
