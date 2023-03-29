/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-02-03
 * Description: provide sandbox controller proxy client
 ******************************************************************************/
#ifndef DAEMON_MODULES_SANDBOX_CONTROLLER_PROXY_CLIENT_PROXY_CLIENT_H
#define DAEMON_MODULES_SANDBOX_CONTROLLER_PROXY_CLIENT_PROXY_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "controller_api.h"

typedef struct _ctrl_client_config_t {
    const char *address;
    const char *controller_type;
    const char *protocol_type;
    // TODO: Add TLS config
} ctrl_client_config_t;

typedef struct _ctrl_client_ops_t ctrl_client_ops_t;

typedef struct _ctrl_client_base_t {
    char *sandboxer;
    char *client_address;
    ctrl_client_ops_t *ops;
} ctrl_client_base_t;

struct _ctrl_client_ops_t {
    int (*create)(const ctrl_client_base_t *client, const char *sandbox_id,
                  const ctrl_create_params_t *params);

    /* sandbox controller ops */
    int (*start)(const ctrl_client_base_t *client, const char *sandbox_id);

    int (*platform)(const ctrl_client_base_t *client, const char *sandbox_id, ctrl_platform_response_t *response);

    int (*prepare)(const ctrl_client_base_t *client, const char *sandbox_id,
                   const ctrl_prepare_params_t *params,
                   ctrl_prepare_response_t *response);

    int (*purge)(const ctrl_client_base_t *client, const char *sandbox_id, const ctrl_purge_params_t *params);

    int (*update_resources)(const ctrl_client_base_t *client, const char *sandbox_id,
                            const ctrl_update_resources_params_t *params);

    int (*stop)(const ctrl_client_base_t *client, const char *sandbox_id, uint32_t timeout);

    int (*wait)(const ctrl_client_base_t *client, const char *sandbox_id, uint32_t *exit_status, uint64_t *exited_at);

    int (*status)(const ctrl_client_base_t *client, const char *sandbox_id,
                  bool verbose, ctrl_status_response_t *response);

    int (*shutdown)(const ctrl_client_base_t *client, const char *sandbox_id);

    ctrl_client_base_t *(*new_client)(const char *sandboxer, const ctrl_client_config_t *config);

    void (*cleanup_client)(ctrl_client_base_t* client);
};

ctrl_client_base_t *ctrl_client_new(const char *sandboxer, const ctrl_client_config_t *config);

void ctrl_client_cleanup(void *client_ptr);

#define __auto_ctrl_client_base_ptr __attribute__((cleanup(ctrl_client_cleanup))) ctrl_client_base_t*

#ifdef __cplusplus
}
#endif

#endif /* DAEMON_MODULES_SANDBOX_CONTROLLER_PROXY_CLIENT_PROXY_CLIENT_H */