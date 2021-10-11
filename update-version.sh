#!/bin/bash
# usage
# ./update-version.sh

#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2019-2021. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description: generate cetification
##- @Author: wujing
##- @Create: 2019-04-25
#######################################################################

function update_release_notes()
{
	LAST_RELEASE=$(git describe --tags --abbrev=0)
	# Prepare proposed delease notes
	rm -f release_notes.tmp
	echo "$(date "+%Y-%m-%d") $USER release $1" >> release_notes.tmp
	git log --first-parent --oneline $LAST_RELEASE.. | cut -d' ' -f 2- | sed 's/^/    - /' >> release_notes.tmp
	echo >> release_notes.tmp
	echo "    dev stats:" >> release_notes.tmp
	echo "      -$(git diff --shortstat $LAST_RELEASE)" >> release_notes.tmp
	echo -n "      - contributors: " >> release_notes.tmp
	git shortlog -ns --no-merges $LAST_RELEASE..HEAD | cut -d$'\t' -f 2 | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/, /g' >> release_notes.tmp
	echo "#" >> release_notes.tmp
	echo "#" >> release_notes.tmp
	echo "#" >> release_notes.tmp
	echo >> release_notes.tmp
	cat release_notes >> release_notes.tmp
	grep -v '^#' release_notes.tmp | sed '/./,$!d' > release_notes
	rm -rf release_notes.tmp
}

topDir=$(git rev-parse --show-toplevel)
specfile="${topDir}/iSulad.spec"
Cmakefile="${topDir}/CMakeLists.txt"
Version_CMakefile="${topDir}/cmake/options.cmake"
old_version=$(cat ${specfile} | grep "%global" | grep "_version" | awk  {'print $3'})
first_old_version=$(cat ${specfile} | grep "%global" | grep "_version" | awk  {'print $3'} | awk -F "." {'print $1'})
second_old_version=$(cat ${specfile} | grep "%global" | grep "_version" | awk  {'print $3'} | awk -F "." {'print $2'})
third_old_version=$(cat ${specfile} | grep "%global" | grep "_version" | awk  {'print $3'} | awk -F "." {'print $3'})
read -p "Which level version do you want to upgrade?[1/2/3/r/N](default:N)  select:" choice
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

if [[ ${choice} -ne "r" ]]; then
	update_release_notes "$new_version"
fi

echo "The version number has been modified: ${old_version} => ${new_version}"

old_release=$(cat ${specfile} | grep "%global" | grep "_release" | awk  {'print $3'})
new_release=$(($old_release+1))
commit_id_long=`git log  --pretty=oneline  -1 | awk {'print $1'}`
echo "The relase version  has been modified, it is ${new_release}"
sed -i "s/set(ISULAD_VERSION \"${old_version}\")/set(ISULAD_VERSION \"${new_version}\")/g" ${Version_CMakefile}
sed -i "s/^.*set(GIT_COMMIT_HASH.*$/set(GIT_COMMIT_HASH \"${commit_id_long}\")/g" ${Cmakefile}
sed -i "s/^\%global _version ${old_version}$/\%global _version ${new_version}/g" ${specfile}
sed -i "s/^\%global _release ${old_release}$/\%global _release ${new_release}/g" ${specfile}

echo "The release number has been modified: ${old_release} => ${new_release}"

