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
##- @Description: generate cetification
##- @Author: lifeng
##- @Create: 2020-03-30
#######################################################################

set +e
set -x

enable_gcov=OFF
ignore_ci=false
basepath=$(cd `dirname $0`; pwd)
source $basepath/helper.sh
TOPDIR=`pwd`
src_code_dir="$TOPDIR"
make_script="${TOPDIR}/CI/make-and-install.sh"
gcov_script="${TOPDIR}/CI/generate_gcov.sh"
CIDIR="$TOPDIR/CI"
testcase_script="${src_code_dir}/CI/run-testcases.sh"
testcase_test="${src_code_dir}/CI/test.sh"
testcase_data="/tmp/testcases_data"
LXC_LOCK_DIR_CONTAINER="/run/lxc/lock/mount_lock"
LXC_LOCK_DIR_HOST="/tmp/lxc_mount_dir"
KEEP_CONTAINERS_ALIVE_DIR="/tmp/containerslock"
TESTCASE_ASSIGN="${CIDIR}/testcase_assign"
BASE_IMAGE=""
devmapper_script="${TOPDIR}/CI/install_devmapper.sh"
disk=NULL

modprobe squashfs
losetup -D
losetup -l
rm -rf ${TESTCASE_ASSIGN}_*

# #Run this file will generate default BASE_IMAGE and auto run isulad unit tests
# #You should cd the root path of isulad, and run:
# ./CI/build.sh

declare -a modules
container_nums=0

function usage() {
    echo "Usage: $0 [options]"
    echo "Continuous integration (CI) script for isulad/lcr project"
    echo "Options:"
    echo "    -m, --module        Execute scripts related to the specified module"
    echo "    -n, --container-num Multiple containers execute scripts in parallel"
    echo "    -g, --enable-gcov   Enable gcov for code coverage analysis"
    echo "    -i, --ignore-ci     Not running testcase"
    echo "    -d, --disk          Specify the disk to create isulad-thinpool"
    echo "        --rm            Auto remove containers after testcase run success"
    echo "    -h, --help          Script help information"
}

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $@" >&2
}

args=`getopt -o m:n:g:i:d:h --long module:,container-num:,enable-gcov:,ignore-ci:,disk:,help -- "$@"`
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi
eval set -- "$args"

while true; do
    case "$1" in
        -m|--module)        modules=${2} ; modules=(${modules// / }) ; shift 2 ;;
        -n|--container-num) container_nums=${2} ; shift 2 ;;
        -g|--enable-gcov)   enable_gcov=${2} ; shift 2 ;;
        -i|--ignore-ci)     ignore_ci=${2} ; shift 2 ;;
        -d|--disk)          disk=${2} ; shift 2 ;;
        -h|--help)          usage ; exit 0 ;;
        --)                 shift ; break ;;
        *)                  err "invalid parameter" ; exit -1 ;;
    esac
done

if [[ "x${enable_gcov}" == "xON" ]]; then
  container_nums=1
fi

declare -A scripts
pwd
TESTCASE_PATH="./CI/test_cases"

for file in $(find ${TESTCASE_PATH} -not \( -path '.*/data' -prune \) -not \( -path "${TESTCASE_PATH}/manual_cases" -prune \) -regextype posix-extended -regex ".*\.(sh)" | grep -v "helpers.sh" | sort)
do
    attributes=$(sed -n '3p' $file)
    if [[ "x$attributes" == "x" ]] || [[ ! "${attributes}" =~ "attributes:" ]];then
        attributes=$(cat $file | grep "# attributes:")
        if [[ "x$attributes" == "x" ]] || [[ ! "${attributes}" =~ "attributes:" ]];then
            continue
        fi
    fi
    attributes=${attributes#*: }
    attributes=(${attributes// / })
    if [[ ${#modules[@]} -ne 0 ]]; then
        intersection=($(comm -12 <(echo ${modules[*]}| tr " " "\n"| sort) <(echo ${attributes[*]} | tr " " "\n"| sort)| sort -g))
        if [[ ${#intersection[@]} -eq 0 ]]; then
            continue
        fi
    fi

    concurrent=$(sed -n '4p' $file)
    concurrent=${concurrent#*: }

    spend_time=$(sed -n '5p' $file)
    spend_time=${spend_time#*: }

    info=(${spend_time} ${concurrent} ${attributes[@]})
    scripts+=([${file}]=${info[@]})
done

function check_concurrent() {
    attr=${scripts[${1}]}
    attributes=(${attr// / })
    #disable concurrent run, testcase may fail while using sleep in testcase due to concurrent
    return 1
    if [[ "x${attributes[1]}" == "xYES" ]];then
        return 0
    fi
    return 1
}

declare -A concurrent_scripts
declare -A non_concurrent_scripts

for script in "${!scripts[@]}"
do
    check_concurrent ${script}
    if [ $? -eq 0 ];then
        concurrent_scripts+=([${script}]=${scripts[${script}]})
    else
        non_concurrent_scripts+=([${script}]=${scripts[${script}]})
    fi
done

CONTAINER_INDEX=1

function calculate_non_concurrent_script_tatol_time() {
    local result=0
    for script in ${!non_concurrent_scripts[@]}
    do
        attr=${non_concurrent_scripts[${script}]}
        attributes=(${attr// / })
        spend_time=${attributes[0]}
        if [[ ${spend_time} == "-" ]]; then
            spend_time=3
        fi
        result=$((result + spend_time))
    done
    echo ${result}
}

function do_testcase_auto_assignment() {
    local index=1
    for script in ${!concurrent_scripts[@]}
    do
        script_realpath=$(realpath ${script})
        echo ${script_realpath} >> ${TESTCASE_ASSIGN}_P${CONTAINER_INDEX}
        index=$((index + 1))
        if [[ ${index} -eq 50 ]]; then
            index=1
            CONTAINER_INDEX=$((CONTAINER_INDEX + 1))
        fi
    done

    if [[ ${#concurrent_scripts[@]} -ne 0 ]]; then
        CONTAINER_INDEX=$((CONTAINER_INDEX + 1))
    fi
    local acc_time=0
    for script in ${!non_concurrent_scripts[@]}
    do
        attr=${non_concurrent_scripts[${script}]}
        attributes=(${attr// / })
        spend_time=${attributes[0]}
        if [[ ${spend_time} == "-" ]]; then
            spend_time=3
        fi

        acc_time=$((acc_time + spend_time))
        if [[ ${acc_time} -ge 200  ]]; then
            acc_time=0
            CONTAINER_INDEX=$((CONTAINER_INDEX + 1))
        fi
        script_realpath=$(realpath ${script})
        echo ${script_realpath} >> ${TESTCASE_ASSIGN}_S${CONTAINER_INDEX}
    done
    if [[ ${#non_concurrent_scripts[@]} -eq 0 ]]; then
        CONTAINER_INDEX=$((CONTAINER_INDEX - 1))
    fi
}

function do_testcase_manual_assignment() {
    local index=1
    rm -rf ${TESTCASE_ASSIGN}_*
    for script in ${!concurrent_scripts[@]}
    do
        script_realpath=$(realpath ${script})
        echo ${script_realpath} >> ${TESTCASE_ASSIGN}_P${CONTAINER_INDEX}
        index=$((index + 1))
        if [[ ${index} -eq 50 ]]; then
            index=1
            CONTAINER_INDEX=$((CONTAINER_INDEX + 1))
        fi
    done

    non_concurrent_tatol_time=$(calculate_non_concurrent_script_tatol_time)

    avg_time_per_container=$((non_concurrent_tatol_time / container_nums))

    if [[ ${#concurrent_scripts[@]} -ne 0 ]]; then
        CONTAINER_INDEX=$((CONTAINER_INDEX + 1))
    fi
    local acc_time=0
    for script in ${!non_concurrent_scripts[@]}
    do
        attr=${non_concurrent_scripts[${script}]}
        attributes=(${attr// / })
        spend_time=${attributes[0]}
        if [[ ${spend_time} == "-" ]]; then
            spend_time=3
        fi
        acc_time=$((acc_time + spend_time))

        if [[ ${acc_time} -gt ${avg_time_per_container} ]]; then
            acc_time=0
            CONTAINER_INDEX=$((CONTAINER_INDEX + 1))
        fi
        script_realpath=$(realpath ${script})
        echo ${script_realpath} >> ${TESTCASE_ASSIGN}_S${CONTAINER_INDEX}
    done
    if [[ ${#non_concurrent_scripts[@]} -eq 0 ]]; then
        CONTAINER_INDEX=$((CONTAINER_INDEX - 1))
    fi
}

if [[ ${container_nums} -le 0 ]]; then
    do_testcase_auto_assignment
else
    do_testcase_manual_assignment ${container_nums}
fi

function echo_success()
{
    echo -e "\033[1;32m"$@"\033[0m"
}

function echo_error()
{
    echo -e "\033[1;31m"$@"\033[0m"
}

DockerFile=./CI/Dockerfile
ProcsFile=/sys/fs/cgroup/cpuset/docker/cgroup.clone_children
function make_sure_cgroup()
{
    image=`cat $DockerFile | grep FROM | awk '{print $2}'`
    if [ ! -e $ProcsFile ];then
        cid=`docker run -d $image`
        if [ $? -ne 0 ];then
            echo "Can not run docker container"
            return 1
        fi
        docker rm -f $cid
    fi
    procsval=`cat $ProcsFile`
    if [ $procsval -ne 1 ];then
        echo "warning: set $ProcsFile to 1"
        echo 1 > $ProcsFile
    fi
}

function make_base_image()
{
    BASE_IMAGE=`docker build -q -f ${DockerFile} .`
}

make_sure_cgroup

make_base_image
if [ $? -ne 0 ];then
    exit 0
fi

#if you want to debug and disable cleanup all resources, create directory by 'mkdir -p $KEEP_CONTAINERS_ALIVE_DIR'
#remember to remove $KEEP_CONTAINERS_ALIVE_DIR after finished your debug.
if [ ! -d $KEEP_CONTAINERS_ALIVE_DIR ];then
    delete_old_resources $time_id "$containers_clear_time" "listcontainers" "remove_container"
    delete_old_resources $time_id "$containers_clear_time" "listtmpdirs" "remove_tmpdir"
fi

RES_CODE=0
mkdir -p $LXC_LOCK_DIR_HOST
env_gcov=""
if [[ "x${enable_gcov}" == "xON" ]]; then
    env_gcov="--env GCOV=ON"
fi

env_ignore_ci=""
if [ "x$ignore_ci" == "xON" ];then
    env_ignore_ci="--env IGNORE_CI=ON"
fi

function exec_script() {
    set +e
    local log_path="/tmp/${1}.log"
    contname="${1}"
    # keep -i so testcases which read stdin can success
    docker exec -itd -e TOPDIR=$src_code_dir -e TESTCASE_FLOCK=/tmp/runflag/${CONTAINER_NAME}.flock -e TESTCASE_SCRIPTS_LOG=/tmp/runflag/${CONTAINER_NAME}.scripts.log \
     -e TESTCASE_RUNFLAG=/tmp/runflag/${CONTAINER_NAME}.runflag -e TESTCASE_CONTNAME=${contname} ${contname} ${testcase_test} run ${2} ${log_path}
    docker exec ${1} $testcase_test get
    if [[ $? -ne 0 ]]; then
        rm -rf ${CIDIR}/${CONTAINER_NAME}.runflag
        docker exec ${contname} cat ${log_path}
        echo_error "testcase execute failed in container ${contname}, log: ${log_path}"
        return 1
    fi
    echo_success "Container: ${contname} success"
    return 0
}

cptemp=${tmpdir_prefix}/${CONTAINER_NAME}_cptemp
# container for testing restful and building
copycontainer=${CONTAINER_NAME}_R1
tmpdir="${tmpdir_prefix}/${copycontainer}"
containers+=(${copycontainer})
mkdir -p ${tmpdir}
touch $CIDIR/${CONTAINER_NAME}.runflag

docker run -tid -v /sys/fs/cgroup:/sys/fs/cgroup --tmpfs /tmp:exec,mode=777 --tmpfs /run:exec,mode=777 --name ${copycontainer} -v ${cptemp}:${cptemp} $env_gcov $env_ignore_ci -v ${CIDIR}:/tmp/runflag -v /lib/modules:/lib/modules -v $testcases_data_dir:$testcase_data -v $LXC_LOCK_DIR_HOST:$LXC_LOCK_DIR_CONTAINER -v $TOPDIR:$src_code_dir -v ${tmpdir}:/var/lib/isulad  --privileged -e login_username=$login_username -e login_passwd=$login_passwd --sysctl net.ipv6.conf.all.disable_ipv6=0 $BASE_IMAGE 
docker cp ${CIDIR}/testcase_assign_R1 ${copycontainer}:/root
echo_success "Run container ${copycontainer} success"

# make and install in rest container
docker exec -e TOPDIR=${src_code_dir} -e BUILDDIR=${cptemp} ${copycontainer} ${make_script}
if [ $? -ne 0 ];then
    echo_error "Make and install failed in container ${copycontainer}"
    rm -rf ${cptemp}
    exit 1
fi
echo_success "Finished build in container ${copycontainer}"

for index in $(seq 1 ${CONTAINER_INDEX})
do
    suffix=$(ls ${CIDIR} | grep testcase_assign_ | grep -E "*[S|P]${index}$" | awk -F '_' '{print $NF}')
    tmpdir="${tmpdir_prefix}/${CONTAINER_NAME}_${suffix}"
    mkdir -p ${tmpdir}
    containers+=(${CONTAINER_NAME}_${suffix})
    docker run -tid -v /sys/fs/cgroup:/sys/fs/cgroup --tmpfs /tmp:exec,mode=777 --tmpfs /run:exec,mode=777 --name ${CONTAINER_NAME}_${suffix} -v ${cptemp}:${cptemp} $env_gcov $env_ignore_ci -v ${CIDIR}:/tmp/runflag -v /lib/modules:/lib/modules -v $testcases_data_dir:$testcase_data -v $LXC_LOCK_DIR_HOST:$LXC_LOCK_DIR_CONTAINER -v $TOPDIR:$src_code_dir -v ${tmpdir}:/var/lib/isulad  -v=/dev:/dev --privileged -e login_username=$login_username -e login_passwd=$login_passwd --sysctl net.ipv6.conf.all.disable_ipv6=0 $BASE_IMAGE
    docker cp ${CIDIR}/testcase_assign_${suffix} ${CONTAINER_NAME}_${suffix}:/root
    echo_success "Run container ${CONTAINER_NAME}_${suffix} success"
done

# disable devmapper for network branch
disk=NULL
if [[ "x$disk" != "xNULL" ]] && [[ "x${enable_gcov}" != "xON" ]] ; then
    # start container to test devicemapper
    devmappercontainer=${CONTAINER_NAME}_devmapper
    containers+=(${devmappercontainer})
    tmpdir="${tmpdir_prefix}/${devmappercontainer}"
    mkdir -p ${tmpdir}
    docker run -tid -v /sys/fs/cgroup:/sys/fs/cgroup --tmpfs /tmp:exec,mode=777 --tmpfs /run:exec,mode=777 --name ${devmappercontainer} -v ${cptemp}:${cptemp} $env_gcov $env_ignore_ci \
    -v ${CIDIR}:/tmp/runflag -v /lib/modules:/lib/modules -v $testcases_data_dir:$testcase_data -v $LXC_LOCK_DIR_HOST:$LXC_LOCK_DIR_CONTAINER \
    -v $TOPDIR:$src_code_dir -v ${tmpdir}:/var/lib/isulad  -v=/dev:/dev --privileged -e login_username=$login_username -e login_passwd=$login_passwd \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 $BASE_IMAGE

    for index in $(seq 1 ${CONTAINER_INDEX})
    do
        suffix=$(ls ${CIDIR} | grep testcase_assign_ | grep -E "*[S|P]${index}$" | awk -F '_' '{print $NF}')
        # only one embedded.sh shell is allowed at the same time and embedded image will not use in devicemapper enviorment
        cat ${CIDIR}/testcase_assign_${suffix} | grep -v embedded.sh >> ${CIDIR}/testcase_assign_devmapper
    done
    docker cp ${CIDIR}/testcase_assign_devmapper ${devmappercontainer}:/root
    echo_success "Run container ${devmappercontainer} success"
fi

for container in ${containers[@]}
do
    {
        docker cp ${cptemp}/cni ${container}:/opt
        docker cp ${cptemp}/bin ${container}:/usr
        docker cp ${cptemp}/etc ${container}:/
        docker cp ${cptemp}/usr/bin ${container}:/usr
        docker cp ${cptemp}/include ${container}:/usr
        docker cp ${cptemp}/lib ${container}:/usr
        docker cp ${cptemp}/systemd ${container}:/lib
        # Docker cannot cp file to tmpfs /tmp in container
        docker exec ${container} sh -c "umask 0022 && cp -r ${testcase_data}/ci_testcase_data/embedded /tmp"
    }&
done
wait

if [[ "x$disk" != "xNULL" ]] && [[ "x${enable_gcov}" != "xON" ]]; then
    # build devicemapper environment
    docker exec -e TOPDIR=${src_code_dir} -e BUILDDIR=${cptemp} ${devmappercontainer} ${devmapper_script} ${disk}
    if [ $? -ne 0 ]; then
        echo_error "Build devicemapper env failed in container ${devmappercontainer}"
        rm -rf ${cptemp}
        exit 1
    fi
    echo_success "Finished build devicemapper in container ${devmappercontainer}"
fi

docker cp ${cptemp}/rest/bin ${copycontainer}:/usr
docker cp ${cptemp}/rest/etc ${copycontainer}:/
docker cp ${cptemp}/rest/include ${copycontainer}:/usr
docker cp ${cptemp}/rest/lib ${copycontainer}:/usr
rm -rf ${cptemp}
# wait for copy files become effective
sleep 3

docker exec ${copycontainer} tail -f --retry /tmp/runflag/${CONTAINER_NAME}.scripts.log 2>/dev/null &
tailpid=$!

for container in ${containers[@]}
do
    {
        exec_script ${container} ${testcase_script}
    }
done

trap "kill -9 $tailpid; exit 0" 15 2

pid_dev="NULL"
if [[ "x$disk" != "xNULL" ]] && [[ "x${enable_gcov}" == "xON" ]]; then
    #build devicemapper environment in containers to generate gcov
    docker exec -e TOPDIR=${src_code_dir} -e BUILDDIR=${cptemp} ${containers[1]} ${devmapper_script} ${disk}
    if [ $? -ne 0 ]; then
        echo_error "Build devicemapper env failed in container ${containers[1]}"
        rm -rf ${cptemp}
        exit 1
    fi
    echo_success "Finished build devicemapper in container ${containers[1]} to generate gcov"

    exec_script ${containers[1]} ${testcase_script} &
    pid_dev="$!"
fi

if [[ "x$pid_dev" != "xNULL" ]]; then
    wait $pid_dev
fi
kill -9 $tailpid

if [[ "x${enable_gcov}" == "xON" ]]; then
  rm -rf ${tmpdir}/build
  docker cp ${containers[1]}:/root/iSulad/build ${tmpdir}
  docker cp ${tmpdir}/build ${containers[0]}:/root
  docker exec -e TOPDIR=${src_code_dir} ${containers[0]} ${gcov_script}
  echo "iSulad GCOV html generated"
  tar xf ./isulad-gcov.tar.gz
  rm -rf /var/www/html/isulad-gcov
  rm -rf /var/www/html/isulad-gcov.tar.gz
  mv ./tmp/isulad-gcov /var/www/html/isulad-gcov
  cp isulad-gcov.tar.gz /var/www/html
  rm -rf ./tmp
fi

if [[ -e $CIDIR/${CONTAINER_NAME}.runflag ]]; then
    echo_success "All \"${#scripts[@]}\" testcases passed!"
    rm -rf $CIDIR/${CONTAINER_NAME}.runflag
    for container in ${containers[@]}
    do
        docker rm -f $container
        rm -rf /var/lib/isulad/$container
    done
    rm -rf /var/lib/isulad/${CONTAINER_NAME}_cptemp
    exit 0;
else
    #for container in ${containers[@]}
    #do
    #    docker rm -f $container
    #    rm -rf /var/lib/isulad/$container
    #done
    #rm -rf /var/lib/isulad/${CONTAINER_NAME}_cptemp
    echo_error "Test failed!"
    exit -1;
fi
