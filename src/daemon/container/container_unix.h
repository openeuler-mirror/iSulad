/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide container unix definition
 ******************************************************************************/
#ifndef __ISULAD_CONTAINER_UNIX_H__
#define __ISULAD_CONTAINER_UNIX_H__

#include <pthread.h>

#include "libisulad.h"
#include "util_atomic.h"
#include "isula_libutils/container_config_v2.h"
#include "isula_libutils/host_config.h"
#include "container_state.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "restartmanager.h"
#include "events_handler.h"
#include "health_check.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

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
    host_config *hostconfig;
    restart_manager_t *rm;
    events_handler_t *handler;
    health_check_manager_t *health_check;

    /* log configs of container */
    char *log_driver;
    char *log_path;
    int log_rotate;
    int64_t log_maxsize;
} container_t;

void container_refinc(container_t *cont);

void container_unref(container_t *cont);

container_t *container_new(const char *runtime, const char *rootpath, const char *statepath, const char *image_id,
                           host_config **hostconfig, container_config_v2_common_config **common_config);

container_t *container_load(const char *runtime, const char *rootpath, const char *statepath, const char *id);

int container_to_disk(const container_t *cont);

int container_to_disk_locking(container_t *cont);

void container_lock(container_t *cont);

int container_timedlock(container_t *cont, int timeout);

void container_unlock(container_t *cont);

char *container_get_env_nolock(const container_t *cont, const char *key);

int v2_spec_make_basic_info(const char *id, const char *name, const char *image_name, const char *image_type,
                            container_config_v2_common_config *v2_spec);

int v2_spec_merge_contaner_spec(container_config_v2_common_config *v2_spec);

char *container_get_command(const container_t *cont);

char *container_get_image(const container_t *cont);

int container_exit_on_next(container_t *cont);

restart_manager_t *get_restart_manager(container_t *cont);

bool reset_restart_manager(container_t *cont, bool reset_count);

void container_update_restart_manager(container_t *cont, const host_config_restart_policy *policy);

void container_reset_manually_stopped(container_t *cont);

void container_wait_stop_cond_broadcast(container_t *cont);
int container_wait_stop(container_t *cont, int timeout);
int container_wait_stop_locking(container_t *cont, int timeout);

void container_wait_rm_cond_broadcast(container_t *cont);
int container_wait_rm_locking(container_t *cont, int timeout);

int save_host_config(const char *id, const char *rootpath, const char *hostconfigstr);
int save_config_v2_json(const char *id, const char *rootpath, const char *v2configstr);

bool has_mount_for(container_t *cont, const char *mpath);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __ISULAD_CONTAINER_UNIX_H__ */
