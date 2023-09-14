#!/bin/bash
#######################################################################
##- Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description: build isulad on many linux distros
##- @Author: haozi007
##- @Create: 2023-09-14
#######################################################################

set +e
set -x

ubuntu_image_name="isulad_on_ubunut:2023"
fedora_image_name="isulad_on_fedora:2023"

ret=0

# prepare docker images, current support fedora and ubuntu
docker build -t ${fedora_image_name} -f ./dockerfiles/Dockerfile-fedora .
docker run --rm -ti -v $(pwd):/test ${fedora_image_name} /test/only_build_isulad.sh
if [ $? -ne 0 ]; then
    echo ">>>>>>>>>>>>>>>>build iSulad on fedora failed>>>>>>>>>>>>>>>>>"
    ret=1
fi

docker build -t ${ubuntu_image_name} -f ./dockerfiles/Dockerfile-ubuntu .
docker run --rm -ti -v $(pwd):/test ${ubuntu_image_name} /test/only_build_isulad.sh
if [ $? -ne 0 ]; then
    echo ">>>>>>>>>>>>>>>>build iSulad on ubuntu failed>>>>>>>>>>>>>>>>>"
    ret=1
fi

exit $ret