/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
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

static int network_create_request_from_rest(evhtp_request_t *req, network_create_request **request)
{
    int ret = 0;
    size_t body_len = 0;
    char *body = NULL;
    parser_error err = NULL;

    ret = get_body(req, &body_len, &body);
    if (ret != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *request = network_create_request_parse_data(body, NULL, &err);
    if (*request == NULL) {
        ERROR("Invalid request body:%s", err);
        ret = -1;
    }

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
        return;
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

    tret = network_create_request_from_rest(req, &request);
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

/* network inspect request check */
static int network_inspect_request_check(network_inspect_request *req)
{
    if (req->name == NULL) {
        ERROR("network name required!");
        return -1;
    }

    return 0;
}

static int network_inspect_request_from_rest(evhtp_request_t *req, network_inspect_request **request)
{
    int ret = 0;
    size_t body_len;
    char *body = NULL;
    parser_error err = NULL;

    ret = get_body(req, &body_len, &body);
    if (ret != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *request = network_inspect_request_parse_data(body, NULL, &err);
    if (*request == NULL) {
        ERROR("Invalid request body:%s", err);
        ret = -1;
        goto out;
    }

    ret = network_inspect_request_check(*request);

out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send network inspect repsponse */
static void evhtp_send_network_inspect_repsponse(evhtp_request_t *req, network_inspect_response *response,
                                                 int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate network inspect response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        return;
    }

    responsedata = network_inspect_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate network inspect json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
}

/* rest network inspect cb */
static void rest_network_inspect_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    network_inspect_request *request = NULL;
    network_inspect_response *response = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->network.inspect == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = network_inspect_request_from_rest(req, &request);
    if (tret < 0) {
        ERROR("bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->network.inspect(request, &response);

    evhtp_send_network_inspect_repsponse(req, response, RESTFUL_RES_OK);

out:
    free_network_inspect_request(request);
    free_network_inspect_response(response);
}

static int network_list_request_from_rest(evhtp_request_t *req, network_list_request **request)
{
    int ret = 0;
    size_t body_len = 0;
    char *body = NULL;
    parser_error err = NULL;

    ret = get_body(req, &body_len, &body);
    if (ret != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *request = network_list_request_parse_data(body, NULL, &err);
    if (*request == NULL) {
        ERROR("Invalid request body:%s", err);
        ret = -1;
    }

    put_body(body);
    free(err);
    return ret;
}

/* evhtp send network list repsponse */
static void evhtp_send_network_list_repsponse(evhtp_request_t *req, network_list_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate network list response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = network_list_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate network list json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
}

/* rest network list cb */
static void rest_network_list_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    network_list_request *request = NULL;
    network_list_response *response = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->network.list == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = network_list_request_from_rest(req, &request);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->network.list(request, &response);

    evhtp_send_network_list_repsponse(req, response, RESTFUL_RES_OK);

out:
    free_network_list_request(request);
    free_network_list_response(response);
}

/* network remove request check */
static int network_remove_request_check(network_remove_request *req)
{
    if (req->name == NULL) {
        ERROR("network name required!");
        return -1;
    }

    return 0;
}

static int network_remove_request_from_rest(evhtp_request_t *req, network_remove_request **request)
{
    int ret = 0;
    size_t body_len = 0;
    char *body = NULL;
    parser_error err = NULL;

    ret = get_body(req, &body_len, &body);
    if (ret != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *request = network_remove_request_parse_data(body, NULL, &err);
    if (*request == NULL) {
        ERROR("Invalid request body:%s", err);
        ret = -1;
        goto out;
    }

    ret = network_remove_request_check(*request);

out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send network remove repsponse */
static void evhtp_send_network_remove_repsponse(evhtp_request_t *req, network_remove_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate network remove response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }
    responsedata = network_remove_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate network remove json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
}

/* rest network remove cb */
static void rest_network_remove_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    network_remove_request *request = NULL;
    network_remove_response *response = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->network.remove == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = network_remove_request_from_rest(req, &request);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->network.remove(request, &response);

    evhtp_send_network_remove_repsponse(req, response, RESTFUL_RES_OK);

out:
    free_network_remove_request(request);
    free_network_remove_response(response);
}

/* rest register network handler */
int rest_register_network_handler(evhtp_t *htp)
{
    if (evhtp_set_cb(htp, NetworkServiceCreate, rest_network_create_cb, NULL) == NULL) {
        ERROR("Failed to register create callback");
        return -1;
    }
    if (evhtp_set_cb(htp, NetworkServiceInspect, rest_network_inspect_cb, NULL) == NULL) {
        ERROR("Failed to register inspect callback");
        return -1;
    }
    if (evhtp_set_cb(htp, NetworkServiceList, rest_network_list_cb, NULL) == NULL) {
        ERROR("Failed to register list callback");
        return -1;
    }
    if (evhtp_set_cb(htp, NetworkServiceRemove, rest_network_remove_cb, NULL) == NULL) {
        ERROR("Failed to register remove callback");
        return -1;
    }
    return 0;
}
