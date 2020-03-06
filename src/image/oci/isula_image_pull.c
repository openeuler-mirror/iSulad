/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: isula image pull operator implement
*******************************************************************************/
#include "isula_image_pull.h"

#include "log.h"
#include "utils.h"
#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "oci_images_store.h"
#include "oci_common_operators.h"

static bool need_new_isula_auth(const im_pull_request *request)
{
    return ((request->username != NULL) || (request->password != NULL) || (request->auth != NULL) ||
            (request->server_address != NULL) || (request->identity_token != NULL) ||
            (request->registry_token != NULL));
}

static int generate_isula_auth_from_im_pull_request(const im_pull_request *request, struct isula_pull_request *ireq)
{
    if (!need_new_isula_auth(request)) {
        return 0;
    }

    ireq->auth = (struct isula_auth_config *)util_common_calloc_s(sizeof(struct isula_auth_config));
    if (ireq->auth == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ireq->auth->username = util_strdup_s(request->username);
    ireq->auth->password = util_strdup_s(request->password);
    ireq->auth->auth = util_strdup_s(request->auth);
    ireq->auth->server_address = util_strdup_s(request->server_address);
    ireq->auth->identity_token = util_strdup_s(request->identity_token);
    ireq->auth->registry_token = util_strdup_s(request->registry_token);

    return 0;
}

static int im_pull_request_to_isula_request(const im_pull_request *request, struct isula_pull_request **ireq)
{
    struct isula_pull_request *tmpreq = NULL;
    int ret = -1;

    if (request == NULL || ireq == NULL) {
        return -1;
    }
    tmpreq = (struct isula_pull_request *)util_common_calloc_s(sizeof(struct isula_pull_request));
    if (tmpreq == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    if (request->image != NULL) {
        tmpreq->image = (struct image_spec *)util_common_calloc_s(sizeof(struct image_spec));
        if (tmpreq->image == NULL) {
            ERROR("Out of memory");
            goto err_out;
        }
        tmpreq->image->image = util_strdup_s(request->image);
    }

    ret = generate_isula_auth_from_im_pull_request(request, tmpreq);
    if (ret != 0) {
        goto err_out;
    }

    *ireq = tmpreq;
    return 0;
err_out:
    free_isula_pull_request(tmpreq);
    return -1;
}

static int isula_pull_response_to_im(const struct isula_pull_response *iresp, im_pull_response **response)
{
    if (iresp == NULL) {
        INFO("Get empty isula response");
        return 0;
    }
    *response = (im_pull_response *)util_common_calloc_s(sizeof(im_pull_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    (*response)->errmsg = util_strdup_s(iresp->errmsg);
    (*response)->image_ref = util_strdup_s(iresp->image_ref);
    return 0;
}

int isula_pull_image(const im_pull_request *request, im_pull_response **response)
{
    isula_image_ops *im_ops = NULL;
    struct isula_pull_request *ireq = NULL;
    struct isula_pull_response *iresp = NULL;
    int ret = -1;
    client_connect_config_t conf = { 0 };
    char *normalized = NULL;

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->pull == NULL) {
        ERROR("Umimplement pull operator");
        return -1;
    }

    ret = im_pull_request_to_isula_request(request, &ireq);
    if (ret != 0) {
        ERROR("Parse im pull request failed");
        return -1;
    }

    iresp = (struct isula_pull_response *)util_common_calloc_s(sizeof(struct isula_pull_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto err_out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto err_out;
    }

    INFO("Send pull image GRPC request");
    ret = im_ops->pull(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Pull image failed: %s", iresp != NULL ? iresp->errmsg : "null");
        goto err_out;
    }

    ret = isula_pull_response_to_im(iresp, response);
    if (ret != 0) {
        ERROR("Parse response failed");
        goto err_out;
    }

    normalized = oci_normalize_image_name(request->image);
    if (normalized == NULL) {
        ret = -1;
        ERROR("Normalize image name %s failed", request->image);
        goto err_out;
    }

    ret = register_new_oci_image_into_memory(normalized);
    if (ret != 0) {
        ERROR("Register image %s into store failed", normalized);
        goto err_out;
    }

    goto out;
err_out:
    free_im_pull_response(*response);
    *response = NULL;
    ret = -1;
out:
    free(normalized);
    free_client_connect_config_value(&conf);
    free_isula_pull_request(ireq);
    free_isula_pull_response(iresp);
    return ret;
}
