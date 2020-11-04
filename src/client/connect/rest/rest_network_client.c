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
    response->path = util_strdup_s(nresponse->path);

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
    if (ret != 0) {
        goto out;
    }
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
    if (ret != 0) {
        goto out;
    }

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

    return 0;
}
