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
 * Description: provide sandboxer client context and ops
 ******************************************************************************/
#include <stdlib.h>
#include "utils.h"
#include "grpc_ctrl_client_ops.h"
#include "grpc_controller_client.h"

#define CONVERT_PROXY_CLIENT(func, client) \
do { \
    if (client == NULL) { \
        ERROR("Invalid proxy client to call "#func""); \
        return -1; \
    } \
    grpc_client = (ctrl_client_grpc_t*)client; \
} while(0)

#define CONTROLLER_PROXY_CLIENT_CALL_ARG2(func, client, sandbox_id, arg1, arg2) \
{ \
    ctrl_client_grpc_t *grpc_client = NULL; \
    CONVERT_PROXY_CLIENT(func, client); \
    return grpc_client->controller_client->func(sandbox_id, arg1, arg2); \
}

#define CONTROLLER_PROXY_CLIENT_CALL_ARG1(func, client, sandbox_id, arg1) \
{ \
    ctrl_client_grpc_t *grpc_client = NULL; \
    CONVERT_PROXY_CLIENT(func, client); \
    return grpc_client->controller_client->func(sandbox_id, arg1); \
}

#define CONTROLLER_PROXY_CLIENT_CALL_ARG0(func, client, sandbox_id) \
{ \
    ctrl_client_grpc_t *grpc_client = NULL; \
    CONVERT_PROXY_CLIENT(func, client); \
    return grpc_client->controller_client->func(sandbox_id); \
}

/* Extension of ctrl_client_ctx_base_t to store grpc client */
typedef struct _ctrl_client_grpc_t {
    ctrl_client_base_t base;
    std::unique_ptr<ControllerClient> controller_client;
} ctrl_client_grpc_t;

static int grpc_ctrl_proxy_create(const ctrl_client_base_t *client, const char *sandbox_id,
                                  const ctrl_create_params_t *params)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG1(create, client, sandbox_id, params)
}

static int grpc_ctrl_proxy_start(const ctrl_client_base_t *client, const char *sandbox_id)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG0(start, client, sandbox_id)
}

static int grpc_ctrl_proxy_platform(const ctrl_client_base_t *client, const char *sandbox_id,
                                    ctrl_platform_response_t *response)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG1(platform, client, sandbox_id, response)
}

static int grpc_ctrl_proxy_prepare(const ctrl_client_base_t *client, const char *sandbox_id,
                                   const ctrl_prepare_params_t *params,
                                   ctrl_prepare_response_t *response)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG2(prepare, client, sandbox_id, params, response)
}

static int grpc_ctrl_proxy_purge(const ctrl_client_base_t *client, const char *sandbox_id,
                                 const ctrl_purge_params_t *params)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG1(purge, client, sandbox_id, params)
}

static int grpc_ctrl_proxy_update_resources(const ctrl_client_base_t *client, const char *sandbox_id,
                                            const ctrl_update_resources_params_t *params)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG1(update_resources, client, sandbox_id, params)
}

static int grpc_ctrl_proxy_stop(const ctrl_client_base_t *client, const char *sandbox_id, uint32_t timeout)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG1(stop, client, sandbox_id, timeout)
}

static int grpc_ctrl_proxy_wait(const ctrl_client_base_t *client, const char *sandbox_id,
                                uint32_t *exit_status, uint64_t *exited_at)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG2(wait, client, sandbox_id, exit_status, exited_at)
}

static int grpc_ctrl_proxy_status(const ctrl_client_base_t *client, const char *sandbox_id,
                                  bool verbose, ctrl_status_response_t *response)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG2(status, client, sandbox_id, verbose, response)
}

static int grpc_ctrl_proxy_shutdown(const ctrl_client_base_t *client, const char *sandbox_id)
{
    CONTROLLER_PROXY_CLIENT_CALL_ARG0(shutdown, client, sandbox_id)
}

static ctrl_client_base_t *grpc_ctrl_client_new(const char *sandboxer, const ctrl_client_config_t *config)
{
    // Create ctrl_client_ctx_grcp_t
    // Implement ops and Create ctrl_client_ops_t
    // Create prox_client_t and return
    if (sandboxer == NULL || config == NULL) {
        ERROR("Invalid arguments for creating controller client");
        return NULL;
    }

    ctrl_client_grpc_t *client = (ctrl_client_grpc_t *)util_common_calloc_s(sizeof(ctrl_client_grpc_t));
    if (client == NULL) {
        ERROR("Failed to allocate memory for controller grpc client");
        return NULL;
    }

    std::unique_ptr<ControllerClient> controller_client(new ControllerClient(sandboxer, config));
    if (controller_client == nullptr) {
        ERROR("Failed to create controller client");
        free(client);
        return NULL;
    }

    client->controller_client = std::move(controller_client);
    return (ctrl_client_base_t*)client;
}

static void grpc_ctrl_client_cleanup(ctrl_client_base_t *client)
{
    if (client == NULL) {
        return;
    }
    ((ctrl_client_grpc_t*)client)->controller_client = nullptr;
    return;
}

ctrl_client_ops_t g_ctrl_grpc_client_ops = {
    .create = grpc_ctrl_proxy_create,
    .start = grpc_ctrl_proxy_start,
    .platform = grpc_ctrl_proxy_platform,
    .prepare = grpc_ctrl_proxy_prepare,
    .purge = grpc_ctrl_proxy_purge,
    .update_resources = grpc_ctrl_proxy_update_resources,
    .stop = grpc_ctrl_proxy_stop,
    .wait = grpc_ctrl_proxy_wait,
    .status = grpc_ctrl_proxy_status,
    .shutdown = grpc_ctrl_proxy_shutdown,
    .new_client = grpc_ctrl_client_new,
    .cleanup_client = grpc_ctrl_client_cleanup
};
