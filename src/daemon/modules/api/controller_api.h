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
 * Description: provide sandbox controller function definition
 ******************************************************************************/

#ifndef DAEMON_MODULES_API_CONTROLLER_API_H
#define DAEMON_MODULES_API_CONTROLLER_API_H

#include <stdint.h>
#include <stdbool.h>
#include "sandbox_api.h"
#include "container_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ctrl_mount_t {
    const char *type;
    const char *source;
    const char *target;
    const char *options;
} ctrl_mount_t;

typedef struct _ctrl_create_params_t {
    ctrl_mount_t *mounts;
    size_t mounts_len;
    const char *config;
    const char *netns_path;
} ctrl_create_params_t;

typedef struct _ctrl_prepare_params_t {
    const char *container_id;
    const char *exec_id;
    const char *oci_spec;
    ctrl_mount_t *rootfs;
    size_t rootfs_len;
    const char *stdin;
    const char *stdout;
    const char *stderr;
    bool terminal;
} ctrl_prepare_params_t;

typedef struct _ctrl_purge_params_t {
    char *container_id;
    char *exec_id;
} ctrl_purge_params_t;

typedef struct _ctrl_update_resources_params_t {
    char *container_id;
    char *resources;
    // TODO: Add annotations
} ctrl_update_resources_params_t;

typedef struct _ctrl_platform_response_t {
    char *os;
    char *architecture;
    char *variant;
} ctrl_platform_response_t;

typedef struct _ctrl_prepare_response_t {
    char *bundle;
} ctrl_prepare_response_t;

typedef struct _ctrl_status_response_t {
    uint32_t pid;
    char *state;
    char *task_address;
    uint64_t created_at;
    uint64_t exited_at;
    // TODO: Add info
    // TODO: Add extra
} ctrl_status_response_t;

struct sb_ctrl_ops {
    bool (*init)();

    bool (*detect)(const char *sandboxer);

    int (*create)(const char *sandboxer, const char *sandbox_id,
                  const ctrl_create_params_t *params);

    /* sandbox controller ops */
    int (*start)(const char *sandboxer, const char *sandbox_id);

    int (*platform)(const char *sandboxer, const char *sandbox_id, ctrl_platform_response_t *response);

    int (*prepare)(const char *sandboxer, const char *sandbox_id,
                   const ctrl_prepare_params_t *params,
                   ctrl_prepare_response_t *response);

    int (*purge)(const char *sandboxer, const char *sandbox_id, const ctrl_purge_params_t *params);

    int (*update_resources)(const char *sandboxer, const char *sandbox_id,
                            const ctrl_update_resources_params_t *params);

    int (*stop)(const char *sandboxer, const char *sandbox_id, uint32_t timeout);

    int (*wait)(const char *sandboxer, const char *sandbox_id, uint32_t *exit_status, uint64_t *exited_at);

    int (*status)(const char *sandboxer, const char *sandbox_id,
                  bool verbose, ctrl_status_response_t *response);

    int (*shutdown)(const char *sandboxer, const char *sandbox_id);
};

typedef enum _sandboxer_type_t {
    SANDBOXER_PROXY = 0,
    SANDBOXER_SHIM = 1
} sandboxer_type_t;

/* Sandbox controller */
int sandbox_ctrl_init();

int sandbox_ctrl_create(const char *sandboxer, const char *sandbox_id,
                        const ctrl_create_params_t *params);

int sandbox_ctrl_start(const char *sandboxer, const char *sandbox_id);

int sandbox_ctrl_platform(const char *sandboxer, const char *sandbox_id,
                          ctrl_platform_response_t *response);

int sandbox_ctrl_prepare(const char *sandboxer, const char *sandbox_id,
                         const ctrl_prepare_params_t *params,
                         ctrl_prepare_response_t *response);

int sandbox_ctrl_purge(const char *sandboxer, const char *sandbox_id,
                       const ctrl_purge_params_t *params);

int sandbox_ctrl_update_resources(const char *sandboxer, const char *sandbox_id,
                                  const ctrl_update_resources_params_t *params);

int sandbox_ctrl_stop(const char *sandboxer, const char *sandbox_id, uint32_t timeout);

int sandbox_ctrl_wait(const char *sandboxer, const char *sandbox_id,
                      uint32_t *exit_status, uint64_t *exited_at);

int sandbox_ctrl_status(const char *sandboxer, const char *sandbox_id,
                        bool verbose, ctrl_status_response_t *response);

int sandbox_ctrl_shutdown(const char *sandboxer, const char *sandbox_id);

#ifdef __cplusplus
}
#endif

#endif /* DAEMON_MODULES_API_CONTROLLER_API_H */
