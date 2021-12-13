#!/bin/bash
#
# attributes: isulad basic container stream exec start attach 
# concurrent: NA
# spend time: 144

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
##- @Description:CI
##- @Author: gaohuatao
##- @Create: 2021-01-19
#######################################################################
declare -r curr_path=$(dirname $(readlink -f "$0"))
source ../helpers.sh

function set_up()
{
	local ret=0
	local image="busybox"
	local test="set_up => (${FUNCNAME[@]})"

	msg_info "${test} starting..."

	check_valgrind_log
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - memory leak before current testcase, please check...." && return ${FAILURE}

	start_isulad_without_valgrind

	isula pull ${image}
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to pull image: ${image}" && return ${FAILURE}

	isula images | grep busybox
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - missing list image: ${image}" && ((ret++))

	CID=$(isula run -itd --runtime runc ${image} sh)
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to run container with image: ${image}" && ((ret++))

	isula exec -it $CID dd if=/dev/zero of=test_500M bs=1M count=500
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create bigdata" && ((ret++))

	msg_info "${test} finished with return ${ret}..."
	return ${ret}
}

function record_origin_status()
{
	origin_isulad_cpu_usage=$(ps -o %cpu -p $(cat /var/run/isulad.pid) | sed -n '2p')
	msg_info "origin isulad cpu usage: $origin_isulad_cpu_usage"

	isulad_shim_pid=$(ps aux | grep "isulad-shim" | grep $CID | awk '{print $2}')
	origin_isulad_shim_cpu_usage=$(ps -o %cpu -p $isulad_shim_pid | sed -n '2p')
	msg_info "origin isulad shim cpu usage: $origin_isulad_shim_cpu_usage"

	rm -rf /iocopy_stream_data_*
}

function check_last_status()
{
	local ret=0
	sleep 5
	ps -T -p $(cat /var/run/isulad.pid) | grep IoCopy
	[[ $? -eq 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - IOCopy Thread residue" && ((ret++))

	last_isulad_cpu_usage=$(ps -o %cpu -p $(cat /var/run/isulad.pid) | sed -n '2p')
	allowable_isulad_cpu_usage=$(echo "$origin_isulad_cpu_usage*2" | bc)
	if [[ $(echo "$allowable_isulad_cpu_usage < 80.0" | bc) -eq 1 ]]; then
		allowable_isulad_cpu_usage=80.0
	fi
	msg_info "allowable isulad cpu usage: $allowable_isulad_cpu_usage"
	if [[ $(echo "$last_isulad_cpu_usage > $allowable_isulad_cpu_usage" | bc) -eq 1 ]]; then
		msg_err "${FUNCNAME[0]}:${LINENO} - Process exception: endless loop or residual thread" && ((ret++))
		ps -o %cpu -p $(cat /var/run/isulad.pid)
	fi

	isulad_shim_pid=$(ps aux | grep "isulad-shim" | grep $CID | awk '{print $2}')
	last_isulad_shim_cpu_usage=$(ps -o %cpu -p $isulad_shim_pid | sed -n '2p')
	allowable_isulad_shim_cpu_usage=$(echo "$origin_isulad_shim_cpu_usage*2" | bc)
	if [[ $(echo "$allowable_isulad_shim_cpu_usage < 1.0" | bc) -eq 1 ]]; then
		allowable_isulad_shim_cpu_usage=1.0
	fi
	msg_info "allowable isulad_shim cpu usage: $allowable_isulad_shim_cpu_usage"
	if [[ $(echo "$last_isulad_shim_cpu_usage > $allowable_isulad_shim_cpu_usage" | bc) -eq 1 ]]; then
		msg_err "${FUNCNAME[0]}:${LINENO} - Process exception: endless loop or residual thread" && ((ret++))
		ps -o %cpu -p $isulad_shim_pid
	fi

	client_pid=$(pidof isula)
	if [[ -n "$client_pid" ]]; then
		msg_err "${FUNCNAME[0]}:${LINENO} - client not exit!!" && ((ret++))
	fi

	ps aux | grep "cat test_" | grep -v "grep"
	if [[ $? -eq 0 ]]; then
		msg_err "${FUNCNAME[0]}:${LINENO} - business process residual" && ((ret++))
	fi

	return ${ret}
}

function test_cat_bigdata()
{
	local ret=0
	local test="test_concurrent_bigdata_stream => (${FUNCNAME[@]})"
	msg_info "${test} starting..."
	declare -a pids

	for index in $(seq 1 5); do
		nohup isula exec -it $CID cat test_500M > /home/iocopy_stream_data_500M_$index &
		pids[${#pids[@]}]=$!
	done
	wait ${pids[*]// /|}

	for index in $(seq 1 5); do
		ls -l /home/iocopy_stream_data_500M_$index
		total_size=$(stat -c"%s" /home/iocopy_stream_data_500M_$index)
		[[ $total_size -ne 524288000 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stream iocopy loss data" && ((ret++))
		rm -f /home/iocopy_stream_data_500M_$index
	done

	check_last_status
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - abnormal status" && ((ret++))

	msg_info "${test} finished with return ${ret}..."
	return ${ret}
}

function test_cat_bigdata_without_pty()
{
	local ret=0
	local test="test_concurrent_bigdata_stream => (${FUNCNAME[@]})"
	msg_info "${test} starting..."
	declare -a pids

	for index in $(seq 1 5); do
		nohup isula exec $CID cat test_500M > /home/iocopy_stream_data_500M_$index &
		pids[${#pids[@]}]=$!
	done
	wait ${pids[*]// /|}

	for index in $(seq 1 5); do
		ls -l /home/iocopy_stream_data_500M_$index
		total_size=$(stat -c"%s" /home/iocopy_stream_data_500M_$index)
		[[ $total_size -ne 524288000 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stream iocopy loss data" && ((ret++))
		rm -f /home/iocopy_stream_data_500M_$index
	done

	check_last_status
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - abnormal status" && ((ret++))

	msg_info "${test} finished with return ${ret}..."
	return ${ret}
}

function test_stream_with_stop_client()
{
	local ret=0
	local test="test_stream_with_stop_client => (${FUNCNAME[@]})"
	msg_info "${test} starting..."

	nohup isula exec $CID cat test_500M > /home/iocopy_stream_data_500M &
	pid=$!
	sleep 2
	kill -19 $pid
	sleep 5
	kill -18 $pid

	wait $pid

	ls -l /home/iocopy_stream_data_500M
	total_size=$(stat -c"%s" /home/iocopy_stream_data_500M)
	[[ $total_size -ne 524288000 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stream iocopy loss data" && ((ret++))

	check_last_status
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - abnormal status" && ((ret++))

	msg_info "${test} finished with return ${ret}..."
	return ${ret}
}

function test_stream_with_kill_client()
{
	local ret=0
	local test="test_stream_with_kill_client => (${FUNCNAME[@]})"
	msg_info "${test} starting..."

	nohup isula exec $CID cat test_500M > /home/iocopy_stream_data_500M &
	pid=$!
	sleep 5
	kill -9 $pid

	check_last_status
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - abnormal status" && ((ret++))

	msg_info "${test} finished with return ${ret}..."
	return ${ret}
}

function test_stream_with_stop_isulad()
{
	local ret=0
	local test="test_stream_with_stop_isulad => (${FUNCNAME[@]})"
	msg_info "${test} starting..."

	nohup isula exec $CID cat test_500M > /home/iocopy_stream_data_500M &
    pid=$!
	sleep 2
	kill -19 $(cat /var/run/isulad.pid)
	sleep 3
	kill -18 $(cat /var/run/isulad.pid) 

	wait $pid 

	ls -l /home/iocopy_stream_data_500M
	total_size=$(stat -c"%s" /home/iocopy_stream_data_500M)
	[[ $total_size -ne 524288000 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - stream iocopy loss data" && ((ret++))

	check_last_status
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - abnormal status" && ((ret++))

	msg_info "${test} finished with return ${ret}..."
	return ${ret}
}

function test_stream_with_kill_isulad()
{
	local ret=0
	local test="test_stream_with_kill_isulad => (${FUNCNAME[@]})"
	msg_info "${test} starting..."

	nohup isula exec $CID cat test_500M > /home/iocopy_stream_data_500M &
	sleep 3
    isulad_pid=$(cat /var/run/isulad.pid)
	kill -9 $isulad_pid
	sleep 1

    check_isulad_stopped $isulad_pid
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - isulad still alive" && ((ret++))

	start_isulad_without_valgrind

	check_last_status
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - abnormal status" && ((ret++))

	msg_info "${test} finished with return ${ret}..."
	return ${ret}
}

function tear_down()
{
	local ret=0
	isula rm -f $CID
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container: $CID" && ((ret++))

	rm -rf //home/iocopy_stream_data_*

	stop_isulad_without_valgrind

	return ${ret}
}

function test_memory_leak_with_bigdata_stream()
{
	local ret=0
	local image="busybox"
	local test="test_memory_leak_with_bigdata_stream => (${FUNCNAME[@]})"
	msg_info "${test} starting..."

	start_isulad_with_valgrind

	CID=$(isula run -itd --runtime runc ${image} sh)

	isula exec -it $CID dd if=/dev/zero of=test_100M bs=1M count=100
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to create bigdata" && ((ret++))

	isula exec -it $CID cat test_100M > /home/iocopy_stream_data_100M
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to cat bigdata from container" && ((ret++))

	rm -rf /home/iocopy_stream_data_100M

	isula rm -f $CID
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - failed to rm container" && ((ret++))

	check_valgrind_log
	[[ $? -ne 0 ]] && msg_err "${FUNCNAME[0]}:${LINENO} - memory leak, please check...." && ((ret++))


	start_isulad_with_valgrind

	msg_info "${test} finished with return ${ret}..."
	return ${ret}
}

declare -i ans=0

set_up || ((ans++))

record_origin_status
test_cat_bigdata || ((ans++))
test_cat_bigdata_without_pty || ((ans++))
test_stream_with_stop_client || ((ans++))
test_stream_with_kill_client || ((ans++))
test_stream_with_stop_isulad || ((ans++))
test_stream_with_kill_isulad || ((ans++))
tear_down || ((ans++))

test_memory_leak_with_bigdata_stream || ((ans++))

show_result ${ans} "${curr_path}/${0}"
