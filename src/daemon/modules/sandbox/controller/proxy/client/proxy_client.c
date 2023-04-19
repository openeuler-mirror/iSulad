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
 * Create: 2023-02-07
 * Description: provide sandbox controller proxy client
 ******************************************************************************/

#include "proxy_client.h"
#include "grpc_ctrl_client_ops.h"

#define PROXY_CONTROLLER "proxy"

static ctrl_client_ops_t *get_ctrl_client_ops(const ctrl_client_config_t *config)
{
    // TODO: This is trivial
    if (strcmp(config->controller_type, PROXY_CONTROLLER) == 0) {
        return &g_ctrl_grpc_client_ops;
    }
    return NULL;
}

ctrl_client_base_t *ctrl_client_new(const char *sandboxer, const ctrl_client_config_t *config)
{
    if (sandboxer == NULL || config == NULL) {
        ERROR("Invalid config for controller client creation");
        return NULL;
    }

    ctrl_client_ops_t *client_ops = get_ctrl_client_ops(config);
    if (client_ops == NULL) {
        ERROR("Controller type not support, controller: %s", config->controller_type);
        return NULL;
    }

    ctrl_client_base_t *client = client_ops->new_client(sandboxer, config);
    if (client == NULL) {
        ERROR("Failed to new controller client");
        return NULL;
    }

    client->ops = client_ops;
    client->sandboxer = util_strdup_s(sandboxer);
    client->client_address = util_strdup_s(config->address);

    return client;
}

void ctrl_client_cleanup(void *client_ptr)
{
    ctrl_client_base_t *client = (ctrl_client_base_t*)client_ptr;
    if (client == NULL) {
        return;
    }
    
    if (client->sandboxer != NULL) {
        free(client->sandboxer);
        client->sandboxer = NULL;
    }

    if (client->client_address != NULL) {
        free(client->client_address);
        client->client_address = NULL;
    }

    if (client->ops != NULL) {
        client->ops->cleanup_client(client);
        client->ops = NULL;
    }

    free(client);
}
