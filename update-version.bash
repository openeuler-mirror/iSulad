#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2019. All rights reserved.
# - iSulad licensed under the Mulan PSL v1.
# - You can use this software according to the terms and conditions of the Mulan PSL v1.
# - You may obtain a copy of Mulan PSL v1 at:
# -     http://license.coscl.org.cn/MulanPSL
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v1 for more details.
##- @Description: generate cetification
##- @Author: wujing
##- @Create: 2019-04-25
#######################################################################
#!/bin/bash
# usage
# ./update-version.bash
topDir=$(git rev-parse --show-toplevel)
specfile="${topDir}/iSulad.spec"
Version_CMakefile="${topDir}/cmake/options.cmake"
old_version=$(cat ${specfile} | grep "%global" | grep "_version" | awk  {'print $3'})
first_old_version=$(cat ${specfile} | grep "%global" | grep "_version" | awk  {'print $3'} | awk -F "." {'print $1'})
second_old_version=$(cat ${specfile} | grep "%global" | grep "_version" | awk  {'print $3'} | awk -F "." {'print $2'})
third_old_version=$(cat ${specfile} | grep "%global" | grep "_version" | awk  {'print $3'} | awk -F "." {'print $3'})
read -p "Which level version do you want to upgrade?[1/2/3/d/N](default:N)  select:" choice
if [[ ! -n "${choice}" || ${choice} == "N" ]]; then
  echo "The version number has not been modified, it is still ${old_version}"
  exit 0
fi

if [[ ${choice} -eq "1" ]]; then
  first_old_version=$(($first_old_version+1))
  second_old_version="0"
  third_old_version="0"
elif [[ ${choice} -eq "2" ]]; then
  second_old_version=$(($second_old_version+1))
  third_old_version="0"
elif [[ ${choice} -eq "3" ]]; then
  third_old_version=$(($third_old_version+1))
fi

new_version=${first_old_version}.${second_old_version}.${third_old_version}

echo "The version number has been modified: ${old_version} => ${new_version}"

old_release=$(cat ${specfile} | grep "%global" | grep "_release" | awk  {'print $3'})
commit_id_long=`git log  --pretty=oneline  -1 | awk {'print $1'}`
commit_id=${commit_id_long:0:8}
new_release=`date "+%Y%m%d"`.`date "+%H%M%S"`.git$commit_id
echo "The relase version  has been modified, it is ${new_release}"
sed -i "s/set(ISULAD_VERSION \"${old_version}\")/set(ISULAD_VERSION \"${new_version}\")/g" ${Version_CMakefile}
sed -i "s/^\%global _version ${old_version}$/\%global _version ${new_version}/g" ${specfile}
sed -i "s/^\%global _release ${old_release}$/\%global _release ${new_release}/g" ${specfile}

echo "The release number has been modified: ${old_release} => ${new_release}"
