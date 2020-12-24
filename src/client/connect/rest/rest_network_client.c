/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2020-09-09
 * Description: provide network restful client functions
 ******************************************************************************/
#include "rest_network_client.h"

#include <unistd.h>
#include "error.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "network.rest.h"
#include "rest_common.h"
#include "utils.h"

/* create request to rest */
static int create_request_to_rest(const struct isula_network_create_request *request, char **body, size_t *body_len)
{
    network_create_request *nrequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    nrequest = util_common_calloc_s(sizeof(network_create_request));
    if (nrequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    nrequest->name = util_strdup_s(request->name);
    nrequest->driver = util_strdup_s(request->driver);
    nrequest->gateway = util_strdup_s(request->gateway);
    nrequest->internal = request->internal;
    nrequest->subnet = util_strdup_s(request->subnet);

    *body = network_create_request_generate_json(nrequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate network create request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_network_create_request(nrequest);
    return ret;
}

/* unpack create response */
static int unpack_create_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_network_create_response *response = (struct isula_network_create_response *)arg;
    network_create_response *nresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        return ret;
    }

    nresponse = network_create_response_parse_data(message->body, NULL, &err);
    if (nresponse == NULL) {
        ERROR("Invalid network create response:%s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = nresponse->cc;
    response->errmsg = util_strdup_s(nresponse->errmsg);
    response->name = util_strdup_s(nresponse->name);

    ret = (nresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_network_create_response(nresponse);
    return ret;
}

/* rest network create */
static int rest_network_create(const struct isula_network_create_request *request,
                               struct isula_network_create_response *response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = create_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead NetworkServiceCreate, body, len, &output);
    if (ret != 0) {
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_create_response, (void *)response);

out:
    buffer_free(output);
    put_body(body);
    return ret;
}

/* inspect request to rest */
static int inspect_request_to_rest(const struct isula_network_inspect_request *request, char **body, size_t *body_len)
{
    network_inspect_request *nrequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    if (request->name == NULL) {
        ERROR("Missing network name in the request");
        return -1;
    }

    nrequest = util_common_calloc_s(sizeof(network_inspect_request));
    if (nrequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    nrequest->name = util_strdup_s(request->name);

    *body = network_inspect_request_generate_json(nrequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate network inspect request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_network_inspect_request(nrequest);
    return ret;
}

/* unpack inspect response */
static int unpack_inspect_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_network_inspect_response *response = (struct isula_network_inspect_response *)arg;
    network_inspect_response *nresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        return ret;
    }

    nresponse = network_inspect_response_parse_data(message->body, NULL, &err);
    if (nresponse == NULL) {
        ERROR("Invalid network inspect response:%s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = nresponse->cc;
    response->json = util_strdup_s(nresponse->network_json);
    response->errmsg = util_strdup_s(nresponse->errmsg);

    ret = (nresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_network_inspect_response(nresponse);
    return ret;
}

/* rest network inspect */
static int rest_network_inspect(const struct isula_network_inspect_request *request,
                                struct isula_network_inspect_response *response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = inspect_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead NetworkServiceInspect, body, len, &output);
    if (ret != 0) {
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_inspect_response, (void *)response);

out:
    buffer_free(output);
    put_body(body);

    return ret;
}

static int package_list_request_filters(const struct isula_filters *src, defs_filters **dst)
{
    size_t i, len;
    defs_filters *filters = NULL;

    filters = (defs_filters *)util_common_calloc_s(sizeof(defs_filters));
    if (filters == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    len = src->len;
    filters->keys = (char **)util_smart_calloc_s(sizeof(char *), len);
    if (filters->keys == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    filters->values = (json_map_string_bool **)util_smart_calloc_s(sizeof(json_map_string_bool *), len);
    if (filters->values == NULL) {
        ERROR("Out of memory");
        free(filters->keys);
        filters->keys = NULL;
        goto free_out;
    }

    for (i = 0; i < src->len; i++) {
        filters->values[filters->len] = (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
        if (filters->values[filters->len] == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        if (append_json_map_string_bool(filters->values[filters->len], src->values[i], true) != 0) {
            free(filters->values[filters->len]);
            filters->values[filters->len] = NULL;
            ERROR("Append failed");
            goto free_out;
        }
        filters->keys[filters->len] = util_strdup_s(src->keys[i]);
        filters->len++;
    }

    *dst = filters;
    filters = NULL;
    return 0;

free_out:
    free_defs_filters(filters);
    return -1;
}

/* list request to rest */
static int list_request_to_rest(const struct isula_network_list_request *request, char **body, size_t *body_len)
{
    int ret = 0;
    network_list_request *nrequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;

    nrequest = (network_list_request *)util_common_calloc_s(sizeof(network_list_request));
    if (nrequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->filters == NULL || request->filters->len == 0) {
        goto pack_json;
    }

    ret = package_list_request_filters(request->filters, &nrequest->filters);
    if (ret != 0) {
        ERROR("Failed to package list request filters");
        goto out;
    }

pack_json:
    *body = network_list_request_generate_json(nrequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate network list request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_network_list_request(nrequest);
    return ret;
}

static int unpack_network_info_for_list_response(const network_list_response *nresponse,
                                                 struct isula_network_list_response *response)
{
    size_t i, num;
    struct isula_network_info **network_info = NULL;

    if (nresponse->networks_len == 0) {
        return 0;
    }

    network_info = (struct isula_network_info **)util_smart_calloc_s(sizeof(struct isula_network_info *),
                                                                     nresponse->networks_len);
    if (network_info == NULL) {
        ERROR("out of memory");
        return -1;
    }

    num = 0;
    for (i = 0; i < nresponse->networks_len; i++) {
        size_t plugin_num = 0;
        int j = 0;

        network_info[i] = (struct isula_network_info *)util_common_calloc_s(sizeof(struct isula_network_info));
        if (network_info[i] == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        num++;
        network_info[i]->name = util_strdup_s(nresponse->networks[i]->name);
        network_info[i]->version = util_strdup_s(nresponse->networks[i]->version);

        plugin_num = nresponse->networks[i]->plugins_len;
        if (plugin_num == 0) {
            network_info[i]->plugin_num = 0;
            network_info[i]->plugins = NULL;
            continue;
        }
        network_info[i]->plugins = (char **)util_smart_calloc_s(sizeof(char *), plugin_num);
        if (network_info[i]->plugins == NULL) {
            ERROR("out of memory");
            goto free_out;
        }

        for (j = 0; j < plugin_num; j++) {
            network_info[i]->plugins[j] = util_strdup_s(nresponse->networks[i]->plugins[j]);
            network_info[i]->plugin_num++;
        }
    }

    response->network_info = network_info;
    network_info = NULL;
    response->network_num = num;
    return 0;

free_out:
    for (i = 0; i < num; i++) {
        isula_network_info_free(network_info[i]);
        network_info[i] = NULL;
    }
    free(network_info);
    network_info = NULL;

    return -1;
}
/* unpack list response */
static int unpack_list_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_network_list_response *response = (struct isula_network_list_response *)arg;
    network_list_response *nresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        return ret;
    }

    nresponse = network_list_response_parse_data(message->body, NULL, &err);
    if (nresponse == NULL) {
        ERROR("Invalid network list response:%s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = nresponse->cc;
    response->errmsg = util_strdup_s(nresponse->errmsg);

    if (unpack_network_info_for_list_response(nresponse, response) != 0) {
        ret = -1;
        goto out;
    }
    ret = (nresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_network_list_response(nresponse);
    return ret;
}

/* rest network list */
static int rest_network_list(const struct isula_network_list_request *request,
                             struct isula_network_list_response *response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = list_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead NetworkServiceList, body, len, &output);
    if (ret != 0) {
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_list_response, (void *)response);

out:
    buffer_free(output);
    put_body(body);
    return ret;
}

/* rest network client ops init */
int rest_network_client_ops_init(isula_connect_ops *ops)
{
    if (ops == NULL) {
        return -1;
    }

    ops->network.create = &rest_network_create;
    ops->network.inspect = &rest_network_inspect;
    ops->network.list = &rest_network_list;

    return 0;
}
