/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
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
 * Description: proxy controller implementation
 ******************************************************************************/

#include <stdlib.h>
#include "proxy_ctrl_ops.h"
#include "map.h"
#include "utils.h"
#include "proxy_client.h"
#include "isulad_config.h"

#define PROXY_GET_CTRL_CLIENT(sandboxer) \
    ctrl_client_base_t *client = get_ctrl_client(sandboxer); \
    if (client == NULL) { \
        ERROR("Cannot find client for sandboxer, %s", sandboxer); \
        ret = -1; \
        break; \
    }

#define CTRL_PROXY_OPER_ARG0(op, sandboxer, sandbox_id) \
do { \
    PROXY_GET_CTRL_CLIENT(sandboxer) \
    ret = client->ops->op(client, sandbox_id); \
} while(0)

#define CTRL_PROXY_OPER_ARG1(op, sandboxer, sandbox_id, arg1) \
do { \
    PROXY_GET_CTRL_CLIENT(sandboxer) \
    ret = client->ops->op(client, sandbox_id, arg1); \
} while(0)

#define CTRL_PROXY_OPER_ARG2(op, sandboxer, sandbox_id, arg1, arg2) \
do { \
    PROXY_GET_CTRL_CLIENT(sandboxer) \
    ret = client->ops->op(client, sandbox_id, arg1, arg2); \
} while(0)


// Add map for indexing sandboxer
// TODO: Need lock or not
static map_t *g_ctrl_clients_map = NULL;

static void ctrl_client_kvfree(void *key, void *value)
{
    free(key);
    ctrl_client_cleanup((ctrl_client_base_t*)value);
}

static void json_sandbox_conf_to_client_config(const defs_map_string_object_sandboxers_element *element,
                                               ctrl_client_config_t *config)
{
    // TODO: Dup or not?
    config->address = element->address;
    config->controller_type = element->controller;
    config->protocol_type = element->protocol;
}

static void create_client(const char *sandboxer, const defs_map_string_object_sandboxers_element *json_conf)
{
    ctrl_client_config_t *config = util_common_calloc_s(sizeof(ctrl_client_config_t));
    if (config == NULL) {
        ERROR("Failed allocate memory for client config, sandboxer: %s", sandboxer);
        return;
    }
    json_sandbox_conf_to_client_config(json_conf, config);
    INFO("Creating sandboxer client for %s", sandboxer);
    ctrl_client_base_t *client = ctrl_client_new(sandboxer, config);
    if (client != NULL) {
        if (map_replace(g_ctrl_clients_map, (void*)sandboxer, (void *)client) == false) {
            ERROR("Failed to add client to map for sandboxer: %s", sandboxer);
            ctrl_client_cleanup(client);
        }
    } else {
        ERROR("Failed to create client for sandboxer: %s", sandboxer);
    }
    free(config);
}

static ctrl_client_base_t *get_ctrl_client(const char *sandboxer)
{
    if (sandboxer == NULL) {
        return NULL;
    }
    return map_search(g_ctrl_clients_map, (void *)sandboxer);
}

bool ctrl_proxy_init()
{
    bool ret = true;
    struct service_arguments *args = NULL;
    defs_map_string_object_sandboxers *sandboxers = NULL;

    DEBUG("Initialize controller proxy");

    if (g_ctrl_clients_map == NULL) {
        g_ctrl_clients_map = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, ctrl_client_kvfree);
        if (g_ctrl_clients_map == NULL) {
            ERROR("Failed to create proxy clients map");
            return false;
        }
    }

    if (isulad_server_conf_rdlock()) {
        return false;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get isulad server config");
        ret = false;
        goto unlock_out;
    }
    
    if (args->json_confs != NULL) {
        sandboxers = args->json_confs->sandboxers;
    }

    if (sandboxers == NULL) {
        ret = false;
        goto unlock_out;
    }

    size_t sandboxer_num = sandboxers->len;
    size_t i;
    for (i = 0; i < sandboxer_num; i++) {
        create_client(sandboxers->keys[i], sandboxers->values[i]);
    }

unlock_out:
    if (isulad_server_conf_unlock()) {
        ERROR("Failed to unlock isulad server config");
        ret = false;
    }
    return ret;
}

bool ctrl_proxy_detect(const char *sandboxer)
{
    if (get_ctrl_client(sandboxer) == NULL) {
        return false;
    }
    return true;
}

int ctrl_proxy_create(const char *sandboxer, const char *sandbox_id,
                      const ctrl_create_params_t *params)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG1(create, sandboxer, sandbox_id, params);
    return ret;
}

int ctrl_proxy_start(const char *sandboxer, const char *sandbox_id)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG0(start, sandboxer, sandbox_id);
    return ret;
}

int ctrl_proxy_platform(const char *sandboxer, const char *sandbox_id,
                        ctrl_platform_response_t *response)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG1(platform, sandboxer, sandbox_id, response);
    return ret;
}

int ctrl_proxy_prepare(const char *sandboxer, const char *sandbox_id,
                       const ctrl_prepare_params_t *params,
                       ctrl_prepare_response_t *response)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG2(prepare, sandboxer, sandbox_id, params, response);
    return ret;
}

int ctrl_proxy_purge(const char *sandboxer, const char *sandbox_id,
                     const ctrl_purge_params_t *params)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG1(purge, sandboxer, sandbox_id, params);
    return ret;
}

int ctrl_proxy_update_resources(const char *sandboxer, const char *sandbox_id,
                                const ctrl_update_resources_params_t *params)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG1(update_resources, sandboxer, sandbox_id, params);
    return ret;
}

int ctrl_proxy_stop(const char *sandboxer, const char *sandbox_id, uint32_t timeout)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG1(stop, sandboxer, sandbox_id, timeout);
    return ret;
}

int ctrl_proxy_wait(const char *sandboxer, const char *sandbox_id,
                    uint32_t *exit_status, uint64_t *exited_at)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG2(wait, sandboxer, sandbox_id, exit_status, exited_at);
    return ret;
}

int ctrl_proxy_status(const char *sandboxer, const char *sandbox_id,
                      bool verbose, ctrl_status_response_t *response)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG2(status, sandboxer, sandbox_id, verbose, response);
    return ret;
}

int ctrl_proxy_shutdown(const char *sandboxer, const char *sandbox_id)
{
    int ret = 0;
    CTRL_PROXY_OPER_ARG0(shutdown, sandboxer, sandbox_id);
    return ret;
}
