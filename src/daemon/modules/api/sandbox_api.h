/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-1-18
 * Description: provide sandbox related api definition
 ******************************************************************************/

#ifndef DAEMON_MODULES_API_SANDBOX_API_H
#define DAEMON_MODULES_API_SANDBOX_API_H
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <isula_libutils/host_config.h>
#include <isula_libutils/sandbox_config.h>
#include "map.h"

typedef enum {
    SANDBOX_UNKNOWN = 0,
    SANDBOX_NOT_READY = 1,
    SANDBOX_READY = 2
} sandbox_status_t;

typedef struct _sandbox_t {
    pthread_mutex_t mutex;
    bool init_mutex;
    // The name here is not the name in CRI metadata
    // It is generated name based on CRI metadata
    char *name;
    uint32_t pid;
    sandbox_status_t status;
    char *sandboxer;
    // created_at is when the sandbox instance is started by controller
    uint64_t created_at;
    // exited_at is when the sandbox instance is stopped by controller
    uint64_t exited_at;
    char *updated_at;
    char *rootpath;
    // TODO: Sandboxer runtime might create its own state dir, so create soft link
    //       to sandboxer state dir?
    char *statepath;
    char *task_address;
    // TODO: A better name
    char *config_option;
    host_config *hostconfig;
    // TODO: Optimize network settings
    sandbox_config *sandboxconfig;

    // Ref counter
    uint64_t refcnt;
} sandbox_t;

/* Sandbox */
sandbox_t *sandbox_new(const char *name, const char *sandboxer, const char *sandbox_rootdir,
                       const char *sandbox_statedir);

bool sandbox_is_ready(sandbox_t *sandbox);

void sandbox_set_ready(sandbox_t *sandbox);

void sandbox_set_not_ready(sandbox_t *sandbox);

int sandbox_fill_host_config(sandbox_t *sandbox, host_config *hostconfig);

int sandbox_fill_sandbox_config(sandbox_t *sandbox, sandbox_config *sandboxconfig);

int sandbox_fill_sandbox_pod_config_option(sandbox_t *sandbox, const char *pod_config_option);

int sandbox_update_status(sandbox_t *sandbox, uint32_t pid, const char *state,
                          const char *task_address, uint64_t created_at, uint64_t exited_at);

int save_sandbox_config_json(const char *id, const char *rootpath, const char *configstr);

int save_sandbox_host_config(const char *id, const char *rootpath, const char *hostconfigstr);

void sandbox_refinc(sandbox_t *sandbox);

void sandbox_unref(sandbox_t *sandbox);

void sandbox_lock(sandbox_t *sandbox);

void sandbox_unlock(sandbox_t *sandbox);

void sandbox_free(sandbox_t *sandbox);

/* Sandbox store */
int sandboxes_store_init(void);

bool sandboxes_store_add(const char *id, sandbox_t *sandbox);

sandbox_t *sandboxes_store_get(const char *id_or_name);

sandbox_t *sandboxes_store_get_by_id(const char *id);

sandbox_t *sandboxes_store_get_by_name(const char *name);

sandbox_t *sandboxes_store_get_by_prefix(const char *prefix);

bool sandboxes_store_remove(const char *id);

// name indexes
int sandbox_name_index_init(void);

bool sandbox_name_index_remove(const char *name);

char *sandbox_name_index_get(const char *name);

bool sandbox_name_index_add(const char *name, const char *id);

map_t *sandbox_name_index_get_all(void);

#endif /* DAEMON_MODULES_API_SANDBOX_API_H */
