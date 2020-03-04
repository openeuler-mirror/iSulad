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
* Description: isula login operator implement
*******************************************************************************/
#include "isula_login.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "libisulad.h"
#include "log.h"

static int is_valid_arguments(const char *server, const char *username, const char *password)
{
    if (server == NULL) {
        isulad_set_error_message("Login requires server address");
        return -1;
    }

    if (username == NULL || password == NULL) {
        isulad_set_error_message("Missing username or password");
        return -1;
    }

    return 0;
}

static int generate_isula_login_request(const char *server, const char *username, const char *password,
                                        struct isula_login_request **ireq)
{
    struct isula_login_request *tmp_req = NULL;

    tmp_req = (struct isula_login_request *)util_common_calloc_s(sizeof(struct isula_login_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    tmp_req->server = util_strdup_s(server);
    tmp_req->username = util_strdup_s(username);
    tmp_req->password = util_strdup_s(password);

    *ireq = tmp_req;
    return 0;
}

int isula_do_login(const char *server, const char *username, const char *password)
{
    int ret = -1;
    struct isula_login_request *ireq = NULL;
    struct isula_login_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    if (is_valid_arguments(server, username, password) != 0) {
        ERROR("Invalid arguments");
        return -1;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->login == NULL) {
        ERROR("Umimplement login operator");
        return -1;
    }

    ret = generate_isula_login_request(server, username, password, &ireq);
    if (ret != 0) {
        goto out;
    }

    iresp = (struct isula_login_response *)util_common_calloc_s(sizeof(struct isula_login_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    ret = im_ops->login(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Failed to login with error: %s", iresp->errmsg);
        isulad_set_error_message("Failed to login with error: %s", iresp->errmsg);
    }

out:
    free_isula_login_request(ireq);
    free_isula_login_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
