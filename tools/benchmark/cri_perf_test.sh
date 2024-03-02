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
##- @Description: perf test
##- @Author: jikai
##- @Create: 2024-02-29
#######################################################################

# cri_perf_test.sh -e $engine -p $parallel

engine=isulad
runtime="unix:///var/run/isulad.sock"
shim="isulad-shim"
parallel=1
while getopts ":e:p:" opt
do
    case $opt in
        e)
            engine=${OPTARG}
            # compare if OPTARG is in ["isulad", "containerd", "crio"]}
            if [ $engine == "isulad" ]; then
                runtime="unix:///var/run/isulad.sock"
                shim="isulad-shim"
            elif [ $engine == "containerd" ]; then
                runtime="unix:///var/run/containerd/containerd.sock"
                shim="containerd-shim"
            elif [ $engine == "crio" ]; then
                runtime="unix:///var/run/crio/crio.sock"
                shim="conmon"
            else
                echo "Unknown engine: ${OPTARG}, only support isulad, containerd, crio."
                exit 1
            fi
            ;;
        p)
            parallel=${OPTARG}
            ;;
        ?)
            echo "Unknown parameter"
            exit 1;;
    esac
done

workdir="$(pwd)"
tmpdir="$workdir/cri_perf_test_tmpdata"
mkdir -p $tmpdir/container/
mkdir -p $tmpdir/pod/
mkdir -p $workdir/cri_perf_test_result/
result_data=$workdir/cri_perf_test_result/${engine}-${parallel}-result.dat
rm -f $result_data

# Get the interval time(ms)
function getTiming(){
    start=$1
    end=$2

    start_s=$(echo $start | cut -d '.' -f 1)
    start_ns=$(echo $start | cut -d '.' -f 2)
    end_s=$(echo $end | cut -d '.' -f 1)
    end_ns=$(echo $end | cut -d '.' -f 2)

    time=$(( ( 10#$end_s - 10#$start_s ) * 1000 + ( 10#$end_ns / 1000000 - 10#$start_ns / 1000000 ) ))

    echo "$time"
}

# Kill all pods and containers running
crictl --runtime-endpoint $runtime rmp -af

# Create $parallel container.json and pod.json
for((i=0;i<$parallel;i++))
do
    cat > $tmpdir/container/container_$i.json << EOF
{
        "metadata": {
             "name": "testcontainer$i"
        },
        "image": {
                "image": "busybox"
        },
        "command": [
                "/bin/sh", "-c", "sleep 1d"
        ],
        "log_path": "console$i.log",
        "linux": {
            "security_context": {
                "capabilities": {}
            }
        }
}
EOF

    cat > $tmpdir/pod/pod_$i.json <<EOF
{
        "metadata": {
                "name": "testpod$i",
                "namespace": "testns",
                "uid": "b49ef5ee-ee30-11ed-a05b-0242ac120003",
                "attempt": 1
        },
        "log_directory": "/tmp",
        "linux": {
            "security_context": {
                "capabilities": {}
            }
        }
}
EOF
done

# get start time
start_time=$(date +%s.%N)

engine_pid=$(pidof $engine)

for((i=0;i<$parallel;i++))
do
    crictl --runtime-endpoint $runtime run --no-pull $tmpdir/container/container_$i.json $tmpdir/pod/pod_$i.json &
done

# wait for all the containers to finish and get end time
end_time=$(date +%s.%N)
boot_time=$(getTiming $start_time $end_time)
a=`crictl --runtime-endpoint $runtime ps | grep testcontainer | wc -l`
while [ $a -ne $parallel ];
do
    a=`crictl --runtime-endpoint $runtime ps | grep testcontainer | wc -l`
    end_time=$(date +%s.%N)
    boot_time=$(getTiming $start_time $end_time)
    if [ $boot_time -gt 2000000 ]; then
        break
    fi
done

if [ ${boot_time} -lt 2000000 ]; then
    echo "BootTime: ${boot_time}ms"
    # Output to the corresponding file
    echo "time: ${boot_time}" >> ${result_data}
else
    echo "${boot_time}ms is too long, please check the environment."
fi

# get pids
shim_pids=$(ps -ef | grep -v grep | grep -i $shim | awk '{print$2}')

# calc memory of pids
engine_mem=$(cat /proc/$engine_pid/status | grep VmRSS | awk '{print $2}')
shim_mem=0
for pid in $shim_pids
do
    let shim_mem+=$(cat /proc/$pid/status | grep VmRSS | awk '{print $2}')
done
echo "Engine Mem: ${engine_mem}KB"
echo "engine-mem: ${engine_mem}" >> ${result_data}
echo "Shim Mem Total: ${shim_mem}KB"
echo "shim-mem: ${shim_mem}" >> ${result_data}

# clean resources
crictl --runtime-endpoint $runtime rmp -af
rm -rf $tmpdir
