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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide image restful service functions
 ******************************************************************************/
#include <unistd.h>

#include "isula_libutils/log.h"
#include "callback.h"
#include "image.rest.h"
#include "rest_service_common.h"
#include "rest_images_service.h"

/* image load request check */
static int image_load_request_check(
    image_load_image_request *req)
{
    if (req->type == NULL) {
        DEBUG("recive NULL Request runtime");
        return -1;
    }

    if (req->file == NULL) {
        DEBUG("container name error");
        return -1;
    }

    return 0;
}

/* image load request from rest */
static int image_load_request_from_rest(evhtp_request_t *req,
                                        image_load_image_request **crequest)
{
    size_t body_len;
    char *body = NULL;
    parser_error err = NULL;
    int ret = 0;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *crequest = image_load_image_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid create request body:%s", err);
        ret = -1;
        goto out;
    }

    if (image_load_request_check(*crequest) < 0) {
        ret = -1;
        goto out;
    }
out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send image load repsponse */
static void evhtp_send_image_load_repsponse(evhtp_request_t *req,
                                            image_load_image_response *response, int rescode)
{
    parser_error err = NULL;
    char *responsedata = NULL;

    responsedata = image_load_image_response_generate_json(response, NULL, &err);
    if (responsedata == NULL) {
        ERROR("Load: failed to generate request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }
    evhtp_send_response(req, responsedata, rescode);

out:
    free(responsedata);
    free(err);
    return;
}

/* image list request from rest */
static int image_list_request_from_rest(evhtp_request_t *req,
                                        image_list_images_request **crequest)
{
    char *body = NULL;
    int ret = 0;
    parser_error err = NULL;
    size_t body_len;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *crequest = image_list_images_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid create request body:%s", err);
        ret = -1;
        goto out;
    }

out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send image list repsponse */
static void evhtp_send_image_list_repsponse(evhtp_request_t *req,
                                            image_list_images_response *response, int rescode)
{
    parser_error err = NULL;
    char *responsedata = NULL;

    responsedata = image_list_images_response_generate_json(response, NULL, &err);
    if (responsedata == NULL) {
        ERROR("List: failed to generate request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }
    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* image delete request check */
static int image_delete_request_check(
    image_delete_image_request *req)
{
    int ret = 0;

    if (req->image_name == NULL) {
        ERROR("container name error");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* image delete request from rest */
static int image_delete_request_from_rest(evhtp_request_t *req,
                                          image_delete_image_request **crequest)
{
    parser_error err = NULL;
    int ret = 0;
    char *body = NULL;
    size_t body_len;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *crequest = image_delete_image_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid create request body:%s", err);
        ret = -1;
        goto out;
    }

    if (image_delete_request_check(*crequest) < 0) {
        ret = -1;
        goto out;
    }
out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send image delete repsponse */
static void evhtp_send_image_delete_repsponse(evhtp_request_t *req,
                                              image_delete_image_response *response, int rescode)
{
    parser_error err = NULL;
    char *responsedata = NULL;

    responsedata = image_delete_image_response_generate_json(response, NULL, &err);
    if (responsedata != NULL) {
        evhtp_send_response(req, responsedata, rescode);
        goto out;
    }

    ERROR("Delete: failed to generate request json:%s", err);
    evhtp_send_reply(req, RESTFUL_RES_ERROR);
out:
    free(responsedata);
    free(err);
    return;
}

/* image inspect request check */
static int image_inspect_request_check(void *req)
{
    int ret = 0;
    image_inspect_request *req_inspect = (image_inspect_request *)req;
    if (req_inspect->id == NULL) {
        DEBUG("image name or id required!");
        ret = -1;
    }

    return ret;
}

/* image inspect request from rest */
static int image_inspect_request_from_rest(const evhtp_request_t *req,
                                           image_inspect_request **crequest)
{
    parser_error err = NULL;
    int ret = 0;
    char *body = NULL;
    size_t body_len;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *crequest = image_inspect_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid create request body:%s", err);
        ret = -1;
        goto out;
    }

    if (image_inspect_request_check(*crequest) < 0) {
        ret = -1;
        goto out;
    }
out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send image inspect repsponse */
static void evhtp_send_image_inspect_repsponse(evhtp_request_t *req,
                                               image_inspect_response *response, int rescode)
{
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    char *responsedata = NULL;

    if (response == NULL) {
        ERROR("Failed to generate inspect response info");
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    responsedata = image_inspect_response_generate_json(response, &ctx, &err);
    if (responsedata == NULL) {
        ERROR("Failed to generate inspect request json:%s", err);
        evhtp_send_reply(req, RESTFUL_RES_ERROR);
        goto out;
    }

    evhtp_send_response(req, responsedata, rescode);

out:
    free(err);
    free(responsedata);
    return;
}

/* rest image load cb */
static void rest_image_load_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_callback_t *cb = NULL;
    image_load_image_request *crequest = NULL;
    image_load_image_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_callback();
    if (cb == NULL || cb->image.load == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_load_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.load(crequest, &cresponse);

    evhtp_send_image_load_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_image_load_image_request(crequest);
    free_image_load_image_response(cresponse);
}

/* rest image list cb */
static void rest_image_list_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_callback_t *cb = NULL;
    image_list_images_request *crequest = NULL;
    image_list_images_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_callback();
    if (cb == NULL || cb->image.list == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_list_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.list(crequest, &cresponse);

    evhtp_send_image_list_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_image_list_images_request(crequest);
    free_image_list_images_response(cresponse);
}

/* rest image delete cb */
static void rest_image_delete_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_callback_t *cb = NULL;
    image_delete_image_request *crequest = NULL;
    image_delete_image_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_callback();
    if (cb == NULL || cb->image.remove == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_delete_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.remove(crequest, &cresponse);

    evhtp_send_image_delete_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_image_delete_image_request(crequest);
    free_image_delete_image_response(cresponse);
}

/* rest image inspect cb */
static void rest_image_inspect_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_callback_t *cb = NULL;
    image_inspect_request *crequest = NULL;
    image_inspect_response *cresponse = NULL;

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_callback();
    if (cb == NULL || cb->image.inspect == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_inspect_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.inspect(crequest, &cresponse);

    evhtp_send_image_inspect_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_image_inspect_request(crequest);
    free_image_inspect_response(cresponse);
}

/* rest register images handler */
int rest_register_images_handler(evhtp_t *htp)
{
    if (evhtp_set_cb(htp, ImagesServiceLoad, rest_image_load_cb, NULL) == NULL) {
        ERROR("Failed to register image load callback");
        return  -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceList, rest_image_list_cb, NULL) == NULL) {
        ERROR("Failed to register image list callback");
        return  -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceDelete, rest_image_delete_cb, NULL) == NULL) {
        ERROR("Failed to register image list callback");
        return  -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceInspect, rest_image_inspect_cb, NULL) == NULL) {
        ERROR("Failed to register image inspect callback");
        return -1;
    }

    return 0;
}

