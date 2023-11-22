/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
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
#include "rest_images_service.h"
#include <unistd.h>
#include <sys/prctl.h>

#include "isula_libutils/log.h"
#include "callback.h"
#include "image.rest.h"
#include "utils.h"
#include "rest_service_common.h"
#include "constants.h"

/* image load request check */
static int image_load_request_check(image_load_image_request *req)
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
static int image_load_request_from_rest(evhtp_request_t *req, image_load_image_request **crequest)
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
static void evhtp_send_image_load_repsponse(evhtp_request_t *req, image_load_image_response *response, int rescode)
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
static int image_list_request_from_rest(evhtp_request_t *req, image_list_images_request **crequest)
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
static void evhtp_send_image_list_repsponse(evhtp_request_t *req, image_list_images_response *response, int rescode)
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
static int image_delete_request_check(image_delete_image_request *req)
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
static int image_delete_request_from_rest(evhtp_request_t *req, image_delete_image_request **crequest)
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
static void evhtp_send_image_delete_repsponse(evhtp_request_t *req, image_delete_image_response *response, int rescode)
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
static int image_inspect_request_from_rest(const evhtp_request_t *req, image_inspect_request **crequest)
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
static void evhtp_send_image_inspect_repsponse(evhtp_request_t *req, image_inspect_response *response, int rescode)
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
    service_executor_t *cb = NULL;
    image_load_image_request *crequest = NULL;
    image_load_image_response *cresponse = NULL;

    prctl(PR_SET_NAME, "ImageLoad");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
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
    service_executor_t *cb = NULL;
    image_list_images_request *crequest = NULL;
    image_list_images_response *cresponse = NULL;

    prctl(PR_SET_NAME, "ImageList");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
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
    service_executor_t *cb = NULL;
    image_delete_image_request *crequest = NULL;
    image_delete_image_response *cresponse = NULL;

    prctl(PR_SET_NAME, "ImageDelete");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
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
    service_executor_t *cb = NULL;
    image_inspect_request *crequest = NULL;
    image_inspect_response *cresponse = NULL;

    prctl(PR_SET_NAME, "ImageInspect");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
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

/* image pull request check */
static int image_pull_request_check(image_pull_image_request *req)
{
    int ret = 0;

    if (req->image_name == NULL) {
        DEBUG("recive NULL Request image name");
        return -1;
    }

    return ret;
}

/* image pull request from rest */
static int image_pull_request_from_rest(evhtp_request_t *req, image_pull_image_request **crequest)
{
    parser_error err = NULL;
    int ret = 0;
    char *body = NULL;
    size_t body_len;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *crequest = image_pull_image_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid pull request body:%s", err);
        ret = -1;
        goto out;
    }

    if (image_pull_request_check(*crequest) < 0) {
        ret = -1;
        goto out;
    }

out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send image pull repsponse */
static void evhtp_send_image_pull_repsponse(evhtp_request_t *req, image_pull_image_response *response, int rescode)
{
    parser_error err = NULL;
    char *responsedata = NULL;

    responsedata = image_pull_image_response_generate_json(response, NULL, &err);
    if (responsedata != NULL) {
        evhtp_send_response(req, responsedata, rescode);
        goto out;
    }

    ERROR("Pull: failed to generate request json:%s", err);
    evhtp_send_reply(req, RESTFUL_RES_ERROR);

out:
    free(responsedata);
    free(err);
    return;
}

/* rest image pull cb */
static void rest_image_pull_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    image_pull_image_request *crequest = NULL;
    image_pull_image_response *cresponse = NULL;

    prctl(PR_SET_NAME, "ImagePull");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->image.pull == NULL) {
        ERROR("Unimplemented pull callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_pull_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.pull(crequest, NULL, &cresponse);

    evhtp_send_image_pull_repsponse(req, cresponse, RESTFUL_RES_OK);

out:
    free_image_pull_image_request(crequest);
    free_image_pull_image_response(cresponse);
}

/* image login request check */
static int image_login_request_check(image_login_request *req)
{
    if (req->username == NULL) {
        DEBUG("Missing username in the request");
        return -1;
    }
    if (req->password == NULL) {
        DEBUG("Missing password in the request");
        return -1;
    }
    if (req->server == NULL) {
        DEBUG("Missing server in the request");
        return -1;
    }
    if (req->type == NULL) {
        DEBUG("Missing type in the request");
        return -1;
    }

    return 0;
}

/* image pull request from rest */
static int image_login_request_from_rest(evhtp_request_t *req, image_login_request **crequest)
{
    parser_error err = NULL;
    int ret = 0;
    char *body = NULL;
    size_t body_len;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *crequest = image_login_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid login request body:%s", err);
        ret = -1;
        goto out;
    }

    if (image_login_request_check(*crequest) < 0) {
        ret = -1;
        goto out;
    }

out:
    util_memset_sensitive_string(body);
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send image pull repsponse */
static void evhtp_send_image_login_repsponse(evhtp_request_t *req, image_login_response *response, int rescode)
{
    parser_error err = NULL;
    char *responsedata = NULL;

    responsedata = image_login_response_generate_json(response, NULL, &err);
    if (responsedata != NULL) {
        evhtp_send_response(req, responsedata, rescode);
        goto out;
    }

    ERROR("Login: failed to generate request json:%s", err);
    evhtp_send_reply(req, RESTFUL_RES_ERROR);

out:
    free(responsedata);
    free(err);
    return;
}

/* rest image login cb */
static void rest_image_login_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    image_login_request *crequest = NULL;
    image_login_response *cresponse = NULL;

    prctl(PR_SET_NAME, "RegistryLogin");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->image.login == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_login_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.login(crequest, &cresponse);

    evhtp_send_image_login_repsponse(req, cresponse, RESTFUL_RES_OK);

out:
    util_memset_sensitive_string(crequest->password);
    free_image_login_request(crequest);
    free_image_login_response(cresponse);
}

/* image logout request check */
static int image_logout_request_check(image_logout_request *req)
{
    return 0;
}

/* image pull request from rest */
static int image_logout_request_from_rest(evhtp_request_t *req, image_logout_request **crequest)
{
    parser_error err = NULL;
    int ret = 0;
    char *body = NULL;
    size_t body_len;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *crequest = image_logout_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid create request body:%s", err);
        ret = -1;
        goto out;
    }

    if (image_logout_request_check(*crequest) < 0) {
        ret = -1;
        goto out;
    }

out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send image logout repsponse */
static void evhtp_send_image_logout_repsponse(evhtp_request_t *req, image_logout_response *response, int rescode)
{
    parser_error err = NULL;
    char *responsedata = NULL;

    responsedata = image_logout_response_generate_json(response, NULL, &err);
    if (responsedata != NULL) {
        evhtp_send_response(req, responsedata, rescode);
        goto out;
    }

    ERROR("Logout: failed to generate request json:%s", err);
    evhtp_send_reply(req, RESTFUL_RES_ERROR);

out:
    free(responsedata);
    free(err);
    return;
}

/* rest image logout cb */
static void rest_image_logout_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    image_logout_request *crequest = NULL;
    image_logout_response *cresponse = NULL;

    prctl(PR_SET_NAME, "RegistryLogout");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->image.logout == NULL) {
        ERROR("Unimplemented logout callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_logout_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.logout(crequest, &cresponse);

    evhtp_send_image_logout_repsponse(req, cresponse, RESTFUL_RES_OK);

out:
    free_image_logout_request(crequest);
    free_image_logout_response(cresponse);
}

/* image tag request from rest */
static int image_tag_request_from_rest(evhtp_request_t *req, image_tag_image_request **crequest)
{
    int ret = 0;
    size_t body_len;
    char *body = NULL;
    parser_error err = NULL;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *crequest = image_tag_image_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid tag request body:%s", err);
        ret = -1;
        goto out;
    }

out:
    put_body(body);
    free(err);
    return ret;
}

/* evhtp send image tag repsponse */
static void evhtp_send_image_tag_repsponse(evhtp_request_t *req, image_tag_image_response *response, int rescode)
{
    parser_error err = NULL;
    char *responsedata = NULL;

    responsedata = image_tag_image_response_generate_json(response, NULL, &err);
    if (responsedata != NULL) {
        evhtp_send_response(req, responsedata, rescode);
        goto out;
    }

    ERROR("Tag: failed to generate request json:%s", err);
    evhtp_send_reply(req, RESTFUL_RES_ERROR);

out:
    free(responsedata);
    free(err);
    return;
}

/* rest image tag cb */
static void rest_image_tag_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    image_tag_image_request *crequest = NULL;
    image_tag_image_response *cresponse = NULL;

    prctl(PR_SET_NAME, "ImageTag");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->image.tag == NULL) {
        ERROR("Unimplemented tag callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_tag_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.tag(crequest, &cresponse);

    evhtp_send_image_tag_repsponse(req, cresponse, RESTFUL_RES_OK);

out:
    free_image_tag_image_request(crequest);
    free_image_tag_image_response(cresponse);
}

/* image import request from rest */
static int image_import_request_from_rest(evhtp_request_t *req, image_import_request **crequest)
{
    int ret = 0;
    size_t body_len;
    char *body = NULL;
    parser_error err = NULL;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }

    *crequest = image_import_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid import request body:%s", err);
        ret = -1;
        goto out;
    }

out:
    put_body(body);
    free(err);

    return ret;
}

/* evhtp send image import repsponse */
static void evhtp_send_image_import_repsponse(evhtp_request_t *req, image_import_response *response, int rescode)
{
    parser_error err = NULL;
    char *response_data = NULL;

    response_data = image_import_response_generate_json(response, NULL, &err);
    if (response_data != NULL) {
        evhtp_send_response(req, response_data, rescode);
        goto out;
    }

    ERROR("Import: failed to generate request json:%s", err);
    evhtp_send_reply(req, RESTFUL_RES_ERROR);

out:
    free(response_data);
    free(err);
}

/* rest image import cb */
static void rest_image_import_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    image_import_request *crequest =  NULL;
    image_import_response *cresponse = NULL;

    prctl(PR_SET_NAME, "ImageImport");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    cb = get_service_executor();
    if (cb == NULL || cb->image.import == NULL) {
        ERROR("Unimplemented import callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_import_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.import(crequest, &cresponse);
    evhtp_send_image_import_repsponse(req, cresponse, RESTFUL_RES_OK);

out:
    free_image_import_request(crequest);
    free_image_import_response(cresponse);
}

#ifdef ENABLE_IMAGE_SEARCH
static int image_search_request_check(const image_search_images_request *req)
{
    int ret = 0;

    if (req->search_name == NULL) {
        ERROR("Recive NULL Request search name");
        return -1;
    }

    if (req->limit < MIN_LIMIT || req->limit > MAX_LIMIT) {
        ERROR("Recive invalid Request search limit");
        return -1;
    }

    return ret;
}

static int image_search_request_from_rest(evhtp_request_t *req, image_search_images_request **crequest)
{
    char *body = NULL;
    int ret = 0;
    parser_error err = NULL;
    size_t body_len;

    if (get_body(req, &body_len, &body) != 0) {
        ERROR("Failed to get body");
        return -1;
    }


    *crequest = image_search_images_request_parse_data(body, NULL, &err);
    if (*crequest == NULL) {
        ERROR("Invalid create request body:%s", err);
        ret = -1;
        goto out;
    }

    if (image_search_request_check(*crequest) < 0) {
        ret = -1;
        goto out;
    }

out:
    put_body(body);
    free(err);
    return ret;
}

static void evhtp_send_image_search_repsponse(evhtp_request_t *req, image_search_images_response *response, int rescode)
{
    parser_error err = NULL;
    char *responsedata = NULL;

    responsedata = image_search_images_response_generate_json(response, NULL, &err);
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

static void rest_image_search_cb(evhtp_request_t *req, void *arg)
{
    int tret;
    service_executor_t *cb = NULL;
    image_search_images_request *crequest = NULL;
    image_search_images_response *cresponse = NULL;

    prctl(PR_SET_NAME, "ImageSearch");

    // only deal with POST request
    if (evhtp_request_get_method(req) != htp_method_POST) {
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }
    cb = get_service_executor();
    if (cb == NULL || cb->image.search == NULL) {
        ERROR("Unimplemented callback");
        evhtp_send_reply(req, RESTFUL_RES_NOTIMPL);
        return;
    }

    tret = image_search_request_from_rest(req, &crequest);
    if (tret < 0) {
        ERROR("Bad request");
        evhtp_send_reply(req, RESTFUL_RES_SERVERR);
        goto out;
    }

    (void)cb->image.search(crequest, &cresponse);

    evhtp_send_image_search_repsponse(req, cresponse, RESTFUL_RES_OK);
out:
    free_image_search_images_request(crequest);
    free_image_search_images_response(cresponse);
}
#endif



/* rest register images handler */
int rest_register_images_handler(evhtp_t *htp)
{
    if (evhtp_set_cb(htp, ImagesServiceLoad, rest_image_load_cb, NULL) == NULL) {
        ERROR("Failed to register image load callback");
        return -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceList, rest_image_list_cb, NULL) == NULL) {
        ERROR("Failed to register image list callback");
        return -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceDelete, rest_image_delete_cb, NULL) == NULL) {
        ERROR("Failed to register image delete callback");
        return -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceInspect, rest_image_inspect_cb, NULL) == NULL) {
        ERROR("Failed to register image inspect callback");
        return -1;
    }

    if (evhtp_set_cb(htp, ImagesServicePull, rest_image_pull_cb, NULL) == NULL) {
        ERROR("Failed to register image pull callback");
        return -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceLogin, rest_image_login_cb, NULL) == NULL) {
        ERROR("Failed to register image login callback");
        return -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceLogout, rest_image_logout_cb, NULL) == NULL) {
        ERROR("Failed to register image logout callback");
        return -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceTag, rest_image_tag_cb, NULL) == NULL) {
        ERROR("Failed to register image logout callback");
        return -1;
    }

    if (evhtp_set_cb(htp, ImagesServiceImport, rest_image_import_cb, NULL) == NULL) {
        ERROR("Failed to register image logout callback");
        return -1;
    }
#ifdef ENABLE_IMAGE_SEARCH
    if (evhtp_set_cb(htp, ImagesServiceSearch, rest_image_search_cb, NULL) == NULL) {
        ERROR("Failed to register image search callback");
        return -1;
    }
#endif

    return 0;
}
