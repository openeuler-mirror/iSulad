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
 * Create: 2020-09-17
 * Description: provide network restful service functions
 ******************************************************************************/
#include "rest_network_service.h"

#include <unistd.h>
#include <string.h>
#include "isula_libutils/log.h"
#include "utils.h"
#include "error.h"
#include "callback.h"
#include "network.rest.h"
#include "rest_service_common.h"

struct rest_handle_st {
    const char *name;
    void *(*request_parse_data)(const char *jsondata, struct parser_context *ctx, parser_error *err);
    int (*request_check)(void *reqeust);
};

/* network create request check */
static int network_create_request_check(void *req)
{
    int ret = 0;

    return ret;
}

static struct rest_handle_st g_rest_handle[] = {
    {
        .name = NetworkServiceCreate,
        .request_parse_data = (void *)network_create_request_parse_data,
        .request_check = network_create_request_check,
    },
};

static int action_request_from_rest(evhtp_request_t *req, void **request, const char *req_type)
{
    char *body = NULL;
    size_t body_len;
    int ret = 0;
    parser_error err = NULL;
    int array_size = 0;
    int i = 0;
    struct rest_handle_st *ops = NULL;

    array_size = sizeof(g_rest_handle) / sizeof(g_rest_handle[0]);
    for (i = 0; i < array_size; i++) {
        if (strcmp(req_type, g_rest_handle[i].name) == 0) {
            ops = &g_rest_handle[i];
            break;
        }
    }
    if (i >= array_size) {
        ERROR("Unknown action type");
        return -1;
    }

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *request = (void *)ops->request_parse_data(body, NULL, &err);
    if (*request == NULL) {
        ERROR("Invalid request body:%s", err);
        ret = -1;
        goto out;
    }

    if (ops->request_check(*request) < 0) {
        ret = -1;
        goto out;
    }

out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send network create repsponse */
static void evhtp_send_network_create_repsponse(evhtp_request_t *req, network_create_response *response, int rescode)
{
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate network create response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = network_create_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Create: failed to generate network create json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest network create cb */
static void rest_network_create_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    network_create_response *response = NULL;
    network_create_request *request = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->network.create == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = action_request_from_rest(req, (void **)&request, NetworkServiceCreate);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->network.create(request, &response);

    evhtp_send_network_create_repsponse(req, response, RESTFUL_RES_OK);

out:
    free_network_create_response(response);
    free_network_create_request(request);
}

/* rest register network handler */
int rest_register_network_handler(evhtp_t *htp)
{
    if (evhtp_set_cb(htp, NetworkServiceCreate, rest_network_create_cb, NULL) == NULL) {
        ERROR("Failed to register create callback");
        return -1;
    }

    return 0;
}
