/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container definition
 ******************************************************************************/
#ifndef __CONTAINER_DEF_H_
#define __CONTAINER_DEF_H_

#include <stdbool.h>
#include <stdint.h>

#include "types_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEFAULT_UNIX_SOCKET
#define DEFAULT_UNIX_SOCKET "unix:///var/run/lcrd.sock"
#endif
#ifndef DEFAULT_ROOTFS_PATH
#define DEFAULT_ROOTFS_PATH "/dev/ram0"
#endif
#ifndef OCICONFIG_PATH
#define OCICONFIG_PATH "/etc/default/lcrd/config.json"
#endif
#ifndef OCI_SYSTEM_CONTAINER_CONFIG_PATH
#define OCI_SYSTEM_CONTAINER_CONFIG_PATH "/etc/default/lcrd/systemcontainer_config.json"
#endif
#ifndef SECCOMP_DEFAULT_PATH
#define SECCOMP_DEFAULT_PATH "/etc/isulad/seccomp_default.json"
#endif
#ifndef OCI_VERSION
#define OCI_VERSION "1.0.0-rc5-dev"
#endif

typedef enum {
    EVENTS_TYPE_EXIT = 0,
    EVENTS_TYPE_STOPPED1 = 1,
    EVENTS_TYPE_STARTING = 2,
    EVENTS_TYPE_RUNNING1 = 3,
    EVENTS_TYPE_STOPPING = 4,
    EVENTS_TYPE_ABORTING = 5,
    EVENTS_TYPE_FREEZING = 6,
    EVENTS_TYPE_FROZEN = 7,
    EVENTS_TYPE_THAWED = 8,
    EVENTS_TYPE_OOM = 9,
    EVENTS_TYPE_CREATE = 10,
    EVENTS_TYPE_START = 11,
    EVENTS_TYPE_EXEC_ADDED = 12,
    EVENTS_TYPE_PAUSED1 = 13,
    EVENTS_TYPE_MAX_STATE = 14
} container_events_type_t;

typedef enum {
    CONTAINER_STATUS_UNKNOWN = 0,
    CONTAINER_STATUS_CREATED = 1,
    CONTAINER_STATUS_STARTING = 2,
    CONTAINER_STATUS_RUNNING = 3,
    CONTAINER_STATUS_STOPPED = 4,
    CONTAINER_STATUS_PAUSED = 5,
    CONTAINER_STATUS_RESTARTING = 6,
    CONTAINER_STATUS_MAX_STATE = 7
} Container_Status;

typedef enum {
    STOPPED, STARTING, RUNNING, STOPPING,
    ABORTING, FREEZING, FROZEN, THAWED, MAX_STATE
} runtime_state_t;

typedef enum {
    HEALTH_SERVING_STATUS_UNKNOWN = 0,
    HEALTH_SERVING_STATUS_SERVING = 1,
    HEALTH_SERVING_STATUS_NOT_SERVING = 2,
    HEALTH_SERVING_STATUS_MAX = 3
} Health_Serving_Status;

typedef enum {
    NAMESPACE_USER = 0,
    NAMESPACE_MNT,
    NAMESPACE_PID,
    NAMESPACE_UTS,
    NAMESPACE_IPC,
    NAMESPACE_NET,
    NAMESPACE_CGROUP,
    NAMESPACE_MAX
} Namespace_Type_t;

typedef enum {
    WAIT_CONDITION_STOPPED = 0,
    WAIT_CONDITION_REMOVED = 1
} wait_condition_t;

typedef struct container_cgroup_resources {
    uint16_t blkio_weight;
    int64_t cpu_shares;
    int64_t cpu_period;
    int64_t cpu_quota;
    int64_t cpu_realtime_period;
    int64_t cpu_realtime_runtime;
    char *cpuset_cpus;
    char *cpuset_mems;
    int64_t memory;
    int64_t memory_swap;
    int64_t memory_reservation;
    int64_t kernel_memory;
    int64_t pids_limit;
    int64_t files_limit;
    int64_t oom_score_adj;
} container_cgroup_resources_t;

typedef struct container_events_format {
    char *id;
    uint32_t has_type;
    container_events_type_t type;
    uint32_t has_pid;
    uint32_t pid;
    uint32_t has_exit_status;
    uint32_t exit_status;
    types_timestamp_t timestamp;
} container_events_format_t;

void container_cgroup_resources_free(container_cgroup_resources_t *cr);


typedef void (*container_events_callback_t)(const container_events_format_t *event);

#ifdef __cplusplus
}
#endif

#endif

