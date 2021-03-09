/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-06-22
 * Description: provide container api definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_API_CONTAINER_API_H
#define DAEMON_MODULES_API_CONTAINER_API_H

#include <pthread.h>
#include <isula_libutils/container_config_v2.h>
#include <isula_libutils/host_config.h>
#include <isula_libutils/oci_runtime_spec.h>
#include <isula_libutils/container_inspect.h>

#include "util_atomic.h"
#include "linked_list.h"
#include "map.h"
#include "utils.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#define MAX_OUTPUT_LEN 4096
#define DEFAULT_PROBE_INTERVAL (30 * Time_Second)
#define DEFAULT_PROBE_TIMEOUT (30 * Time_Second)
#define DEFAULT_START_PERIOD (0 * Time_Second)
#define DEFAULT_PROBE_RETRIES 3
#define MAX_LOG_ENTRIES 5
#define EXIT_STATUS_HEALTHY 0

#define NO_HEALTH_CHECK "none"
#define HEALTH_STARTING "starting"
#define HEALTHY "healthy"
#define UNHEALTHY "unhealthy"

typedef enum { MONITOR_IDLE = 0, MONITOR_INTERVAL = 1, MONITOR_STOP = 2 } health_check_monitor_status_t;

typedef struct health_check_manager {
    pthread_mutex_t mutex;
    bool init_mutex;
    health_check_monitor_status_t monitor_status;
    // Used to wait for the health check minotor thread to close
    bool monitor_exist;
} health_check_manager_t;

typedef struct _container_state_t_ {
    pthread_mutex_t mutex;
    container_state *state;
} container_state_t;

typedef struct _restart_manager_t {
    pthread_mutex_t mutex;
    bool init_mutex;
    pthread_cond_t wait_cancel_con;
    bool init_wait_cancel_con;
    uint64_t refcnt;
    host_config_restart_policy *policy;
    int failure_count;
    int64_t timeout;
    bool active;
    bool canceled;
} restart_manager_t;

typedef struct _container_events_handler_t {
    pthread_mutex_t mutex;
    bool init_mutex;
    struct linked_list events_list;
    bool has_handler;
} container_events_handler_t;

typedef struct _container_t_ {
    pthread_mutex_t mutex;
    bool init_mutex;
    pthread_cond_t wait_stop_con;
    bool init_wait_stop_con;
    pthread_cond_t wait_rm_con;
    bool init_wait_rm_con;
    uint64_t refcnt;
    char *runtime;
    char *root_path;
    char *state_path;
    char *image_id;
    container_config_v2_common_config *common_config;
    container_state_t *state;
    // skip remove network when restarting
    bool skip_remove_network;
    container_network_settings *network_settings;
    host_config *hostconfig;
    restart_manager_t *rm;
    container_events_handler_t *handler;
    health_check_manager_t *health_check;
    bool rm_anonymous_volumes;

    /* log configs of container */
    char *log_driver;
    char *log_path;
    int log_rotate;
    int64_t log_maxsize;
} container_t;

int containers_store_init(void);

bool containers_store_add(const char *id, container_t *cont);

container_t *containers_store_get(const char *id_or_name);

container_t *containers_store_get_by_prefix(const char *prefix);

bool containers_store_remove(const char *id);

int containers_store_list(container_t ***out, size_t *size);

char **containers_store_list_ids(void);

/* name indexs */
int container_name_index_init(void);

bool container_name_index_remove(const char *name);

char *container_name_index_get(const char *name);

bool container_name_index_add(const char *name, const char *id);

map_t *container_name_index_get_all(void);

bool container_name_index_rename(const char *new_name, const char *old_name, const char *id);

void container_refinc(container_t *cont);

void container_unref(container_t *cont);

container_t *container_new(const char *runtime, const char *rootpath, const char *statepath, const char *image_id);

int container_fill_v2_config(container_t *cont, container_config_v2_common_config *common_config);

int container_fill_host_config(container_t *cont, host_config *hostconfig);

int container_fill_state(container_t *cont, container_state *state);

int container_fill_restart_manager(container_t *cont);

int container_fill_network_settings(container_t *cont, container_network_settings *network_settings);

container_t *container_load(const char *runtime, const char *rootpath, const char *statepath, const char *id);

int container_to_disk(const container_t *cont);

int container_to_disk_locking(container_t *cont);

int container_state_to_disk(const container_t *cont);

int container_state_to_disk_locking(container_t *cont);

int container_network_settings_to_disk(const container_t *cont);

int container_network_settings_to_disk_locking(container_t *cont);

void container_lock(container_t *cont);

int container_timedlock(container_t *cont, int timeout);

void container_unlock(container_t *cont);

char *container_get_env_nolock(const container_t *cont, const char *key);

int container_v2_spec_merge_contaner_spec(container_config_v2_common_config *v2_spec);

char *container_get_command(const container_t *cont);

char *container_get_image(const container_t *cont);

int container_exit_on_next(container_t *cont);

bool container_reset_restart_manager(container_t *cont, bool reset_count);

void container_update_restart_manager(container_t *cont, const host_config_restart_policy *policy);

void container_wait_stop_cond_broadcast(container_t *cont);
int container_wait_stop(container_t *cont, int timeout);
int container_wait_stop_locking(container_t *cont, int timeout);

void container_wait_rm_cond_broadcast(container_t *cont);
int container_wait_rm_locking(container_t *cont, int timeout);

bool container_has_mount_for(container_t *cont, const char *mpath);

container_state *container_dup_state(container_state_t *s);

container_inspect_state *container_state_to_inspect_state(container_state_t *s);

void container_restart_update_start_and_finish_time(container_state_t *s, const char *finish_at);

void container_state_set_starting(container_state_t *s);

void container_state_reset_starting(container_state_t *s);

void container_state_set_running(container_state_t *s, const pid_ppid_info_t *pid_info, bool initial);

void container_state_set_stopped(container_state_t *s, int exit_code);

void container_state_set_restarting(container_state_t *s, int exit_code);

void container_state_set_paused(container_state_t *s);
void container_state_reset_paused(container_state_t *s);

void container_state_set_dead(container_state_t *s);

void container_state_increase_restart_count(container_state_t *s);

void container_state_reset_restart_count(container_state_t *s);

int container_state_get_restart_count(container_state_t *s);

bool container_state_get_has_been_manual_stopped(container_state_t *s);

void container_state_set_has_been_manual_stopped(container_state_t *s);

void container_state_reset_has_been_manual_stopped(container_state_t *s);

// container_state_set_removal_in_progress sets the container state as being removed.
// It returns true if the container was already in that state
bool container_state_set_removal_in_progress(container_state_t *s);

void container_state_reset_removal_in_progress(container_state_t *s);

const char *container_state_to_string(Container_Status cs);

Container_Status container_state_judge_status(const container_state *state);

Container_Status container_state_get_status(container_state_t *s);

bool container_is_running(container_state_t *s);

bool container_is_restarting(container_state_t *s);

bool container_is_removal_in_progress(container_state_t *s);

bool container_is_paused(container_state_t *s);

uint32_t container_state_get_exitcode(container_state_t *s);

int container_state_get_pid(container_state_t *s);

bool container_is_dead(container_state_t *s);

void container_state_set_error(container_state_t *s, const char *err);

char *container_state_get_started_at(container_state_t *s);

bool container_is_valid_state_string(const char *state);

int container_dup_health_check_status(defs_health **dst, const defs_health *src);

void container_update_health_monitor(const char *container_id);

extern int container_supervisor_add_exit_monitor(int fd, const pid_ppid_info_t *pid_info, const char *name,
                                                 const char *runtime);

extern char *container_exit_fifo_create(const char *cont_state_path);

extern int container_exit_fifo_open(const char *cont_exit_fifo);

void container_init_health_monitor(const char *id);
void container_stop_health_checks(const char *container_id);

bool container_is_in_gc_progress(const char *id);

int container_module_init(char **msg);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif // DAEMON_MODULES_API_CONTAINER_API_H
