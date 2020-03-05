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
#define DEFAULT_UNIX_SOCKET "unix:///var/run/isulad.sock"
#endif
#ifndef DEFAULT_ROOTFS_PATH
#define DEFAULT_ROOTFS_PATH "/dev/ram0"
#endif
#ifndef OCICONFIG_PATH
#define OCICONFIG_PATH "/etc/default/isulad/config.json"
#endif
#ifndef OCI_SYSTEM_CONTAINER_CONFIG_PATH
#define OCI_SYSTEM_CONTAINER_CONFIG_PATH "/etc/default/isulad/systemcontainer_config.json"
#endif
#ifndef SECCOMP_DEFAULT_PATH
#define SECCOMP_DEFAULT_PATH "/etc/isulad/seccomp_default.json"
#endif
#ifndef OCI_VERSION
#define OCI_VERSION "1.0.1"
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
    EVENTS_TYPE_START,
    EVENTS_TYPE_RESTART,
    EVENTS_TYPE_STOP,
    EVENTS_TYPE_EXEC_CREATE,
    EVENTS_TYPE_EXEC_START,
    EVENTS_TYPE_EXEC_DIE,
    EVENTS_TYPE_ATTACH,
    EVENTS_TYPE_KILL,
    EVENTS_TYPE_TOP,
    EVENTS_TYPE_RENAME,
    EVENTS_TYPE_ARCHIVE_PATH,
    EVENTS_TYPE_EXTRACT_TO_DIR,
    EVENTS_TYPE_UPDATE,
    EVENTS_TYPE_PAUSE,
    EVENTS_TYPE_UNPAUSE,
    EVENTS_TYPE_EXPORT,
    EVENTS_TYPE_RESIZE,
    EVENTS_TYPE_PAUSED1,
    EVENTS_TYPE_MAX_STATE
} container_events_type_t;

typedef enum {
    EVENTS_TYPE_IMAGE_LOAD = 0,
    EVENTS_TYPE_IMAGE_REMOVE,
    EVENTS_TYPE_IMAGE_PULL,
    EVENTS_TYPE_IMAGE_LOGIN,
    EVENTS_TYPE_IMAGE_LOGOUT,
    EVENTS_TYPE_IMAGE_MAX_STATE
} image_events_type_t;

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
    EXIT, STOPPED, STARTING, RUNNING, STOPPING, ABORTING, FREEZING,
    FROZEN, THAWED, OOM, CREATE, START, RESTART, STOP, EXEC_CREATE, EXEC_START, EXEC_DIE, ATTACH,
    KILL, TOP, RENAME, ARCHIVE_PATH, EXTRACT_TO_DIR, UPDATE, PAUSE, UNPAUSE, EXPORT, RESIZE, PAUSED1, MAX_STATE,
} runtime_state_t;

typedef enum {
    IM_LOAD, IM_REMOVE, IM_PULL, IM_LOGIN, IM_LOGOUT
} image_state_t;


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

typedef enum {
    CONTAINER_EVENT,
    IMAGE_EVENT
} msg_event_type_t;

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
    int64_t swappiness;
} container_cgroup_resources_t;

typedef struct container_events_format {
    types_timestamp_t timestamp;
    char *opt;
    char *id;
    char **annotations;
    char annotations_len;
} container_events_format_t;

void container_cgroup_resources_free(container_cgroup_resources_t *cr);

void container_events_format_free(container_events_format_t *value);

typedef void (*container_events_callback_t)(const container_events_format_t *event);

#ifdef __cplusplus
}
#endif

#endif

