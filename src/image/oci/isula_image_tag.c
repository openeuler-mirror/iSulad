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
* Author: wangfengtu
* Create: 2020-04-15
* Description: isula image tag operator implement
*******************************************************************************/
#include "isula_image_tag.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "isula_libutils/log.h"

static int generate_isula_tag_request(const char *src_name, const char *dest_name, struct isula_tag_request **ireq)
{
    struct isula_tag_request *tmp_req = NULL;
    int ret = 0;

    if (src_name == NULL || dest_name == NULL || ireq == NULL) {
        ERROR("Required image name");
        return -1;
    }
    tmp_req = (struct isula_tag_request *)util_common_calloc_s(sizeof(struct isula_tag_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    tmp_req->src_name = (struct image_spec *)util_common_calloc_s(sizeof(struct image_spec));
    if (tmp_req->src_name == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    tmp_req->dest_name = (struct image_spec *)util_common_calloc_s(sizeof(struct image_spec));
    if (tmp_req->dest_name == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    tmp_req->src_name->image = util_strdup_s(src_name);
    tmp_req->dest_name->image = util_strdup_s(dest_name);

out:
    *ireq = tmp_req;
    return ret;
}

int isula_image_tag(const char *src_name, const char *dest_name, char **errmsg)
{
    int ret = -1;
    struct isula_tag_request *ireq = NULL;
    struct isula_tag_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->tag == NULL) {
        ERROR("Umimplement tag operator");
        return -1;
    }

    ret = generate_isula_tag_request(src_name, dest_name, &ireq);
    if (ret != 0) {
        goto out;
    }

    iresp = (struct isula_tag_response *)util_common_calloc_s(sizeof(struct isula_tag_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    INFO("Send remove image GRPC request");
    ret = im_ops->tag(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Tag image %s to %s failed: %s", src_name, dest_name, iresp->errmsg);
    }
    *errmsg = iresp->errmsg;
    iresp->errmsg = NULL;

out:
    free_isula_tag_request(ireq);
    free_isula_tag_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
