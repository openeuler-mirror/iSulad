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
* Description: isula image rootfs remove operator implement
*******************************************************************************/
#include "isula_logout.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "libisulad.h"
#include "log.h"

static int generate_isula_logout_request(const char *server, struct isula_logout_request **ireq)
{
    struct isula_logout_request *tmp_req = NULL;

    tmp_req = (struct isula_logout_request *)util_common_calloc_s(sizeof(struct isula_logout_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    tmp_req->server = util_strdup_s(server);

    *ireq = tmp_req;
    return 0;
}

static inline int is_valid_arguments(const char *server)
{
    if (server == NULL) {
        isulad_set_error_message("Logout requires server address");
        return -1;
    }
    return 0;
}

int isula_do_logout(const char *server)
{
    int ret = -1;
    struct isula_logout_request *ireq = NULL;
    struct isula_logout_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    if (is_valid_arguments(server) != 0) {
        ERROR("Invlaid arguments");
        return -1;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }

    if (im_ops->logout == NULL) {
        ERROR("Umimplement logout operator");
        return -1;
    }

    ret = generate_isula_logout_request(server, &ireq);
    if (ret != 0) {
        goto out;
    }

    iresp = (struct isula_logout_response *)util_common_calloc_s(sizeof(struct isula_logout_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    ret = im_ops->logout(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Failed to logout with error: %s", iresp->errmsg);
        isulad_set_error_message("Failed to logout with error: %s", iresp->errmsg);
    }

out:
    free_isula_logout_request(ireq);
    free_isula_logout_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
