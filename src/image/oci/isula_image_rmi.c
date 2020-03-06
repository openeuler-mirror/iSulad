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
#include "isula_image_rmi.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "log.h"

static int generate_isula_rmi_request(const char *image, bool force, struct isula_rmi_request **ireq)
{
    struct isula_rmi_request *tmp_req = NULL;
    int ret = 0;

    if (image == NULL) {
        ERROR("Required image name");
        return -1;
    }
    tmp_req = (struct isula_rmi_request *)util_common_calloc_s(sizeof(struct isula_rmi_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    tmp_req->image = (struct image_spec *)util_common_calloc_s(sizeof(struct image_spec));
    if (tmp_req->image == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    tmp_req->image->image = util_strdup_s(image);
    tmp_req->force = force;

out:
    *ireq = tmp_req;
    return ret;
}

int isula_image_rmi(const char *image, bool force, char **errmsg)
{
    int ret = -1;
    struct isula_rmi_request *ireq = NULL;
    struct isula_rmi_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->rmi == NULL) {
        ERROR("Umimplement rmi operator");
        return -1;
    }

    ret = generate_isula_rmi_request(image, force, &ireq);
    if (ret != 0) {
        goto out;
    }

    iresp = (struct isula_rmi_response *)util_common_calloc_s(sizeof(struct isula_rmi_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    INFO("Send remove image GRPC request");
    ret = im_ops->rmi(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Rmi image %s failed: %s", image, iresp->errmsg);
    }
    *errmsg = iresp->errmsg;
    iresp->errmsg = NULL;

out:
    free_isula_rmi_request(ireq);
    free_isula_rmi_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
