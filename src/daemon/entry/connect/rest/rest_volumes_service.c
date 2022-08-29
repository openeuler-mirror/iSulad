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
 * Author: zhongtao
 * Create: 2022-08-26
 * Description: provide volumes restful service functions
 ******************************************************************************/
#include "rest_volumes_service.h"

#include <unistd.h>
#include <string.h>
#include <isula_libutils/log.h>
#include <error.h>
#include "utils.h"
#include "callback.h"
#include "volumes.rest.h"
#include "rest_service_common.h"

static int volumes_list_request_from_rest(evhtp_request_t *req, volume_list_volume_request **request)
{
    int ret;
    size_t body_len = 0;
    char *body = NULL;
    parser_error err = NULL;

    ret = get_body(req, &body_len, &body);
    if (ret != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *request = volume_list_volume_request_parse_data(body, NULL, &err);
    if (*request == NULL) {
        ERROR("Invalid request body:%s", err);
        ret = -1;
    }

    UTIL_FREE_AND_SET_NULL(err);
    put_body(body);
    return ret;
}

static void evhtp_send_volumes_list_repsponse(evhtp_request_t *req, volume_list_volume_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate volume list response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        return;
    }

    responsedata = volume_list_volume_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate volume list json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    UTIL_FREE_AND_SET_NULL(responsedata);
    UTIL_FREE_AND_SET_NULL(err);
}

static void rest_volumes_list_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    volume_list_volume_request *request = NULL;
    volume_list_volume_response *response = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    cb = get_service_executor();
    if (cb == NULL || cb->volume.list == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = volumes_list_request_from_rest(req, &request);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->volume.list(request, &response);

    evhtp_send_volumes_list_repsponse(req, response, RESTFUL_RES_OK);

out:
    free_volume_list_volume_response(response);
    free_volume_list_volume_request(request);
}

static int volumes_remove_request_check(const volume_remove_volume_request *req)
{
    if (req->name == NULL) {
        ERROR("Volume name required!");
        return -1;
    }

    return 0;
}

static int volumes_remove_request_from_rest(evhtp_request_t *req, volume_remove_volume_request **request)
{
    int ret;
    size_t body_len = 0;
    char *body = NULL;
    parser_error err = NULL;

    ret = get_body(req, &body_len, &body);
    if (ret != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *request = volume_remove_volume_request_parse_data(body, NULL, &err);
    if (*request == NULL) {
        ERROR("Invalid request body:%s", err);
        ret = -1;
        goto out;
    }

    ret = volumes_remove_request_check(*request);

out:
    UTIL_FREE_AND_SET_NULL(err);
    put_body(body);
    return ret;
}

static void evhtp_send_volumes_remove_repsponse(evhtp_request_t *req, volume_remove_volume_response *response,
                                                int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate volume remove response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = volume_remove_volume_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate volume remove json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    UTIL_FREE_AND_SET_NULL(responsedata);
    UTIL_FREE_AND_SET_NULL(err);
}

static void rest_volumes_remove_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    volume_remove_volume_request *request = NULL;
    volume_remove_volume_response *response = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    cb = get_service_executor();
    if (cb == NULL || cb->volume.remove == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = volumes_remove_request_from_rest(req, &request);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->volume.remove(request, &response);

    evhtp_send_volumes_remove_repsponse(req, response, RESTFUL_RES_OK);

out:
    free_volume_remove_volume_response(response);
    free_volume_remove_volume_request(request);
}

int rest_register_volumes_handler(evhtp_t *htp)
{
    if (evhtp_set_cb(htp, VolumesServiceList, rest_volumes_list_cb, NULL) == NULL) {
        ERROR("Failed to register list callback");
        return -1;
    }

    if (evhtp_set_cb(htp, VolumesServiceRemove, rest_volumes_remove_cb, NULL) == NULL) {
        ERROR("Failed to register remove callback");
        return -1;
    }

    return 0;
}

