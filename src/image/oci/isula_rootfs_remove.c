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
#include "isula_rootfs_remove.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "log.h"

static int generate_isula_remove_request(const char *name_id, struct isula_remove_request **ireq)
{
    struct isula_remove_request *tmp_req = NULL;

    if (name_id == NULL) {
        ERROR("Invalid container id or name");
        return -1;
    }
    tmp_req = (struct isula_remove_request *)util_common_calloc_s(sizeof(struct isula_remove_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    tmp_req->name_id = util_strdup_s(name_id);

    *ireq = tmp_req;
    return 0;
}

int isula_rootfs_remove(const char *name_id)
{
#define CONTAINER_NOT_KNOWN_ERR "container not known"
    int ret = 0;
    int nret = -1;
    struct isula_remove_request *ireq = NULL;
    struct isula_remove_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->remove == NULL) {
        ERROR("Umimplement remove operator");
        return -1;
    }

    nret = generate_isula_remove_request(name_id, &ireq);
    if (nret != 0) {
        ret = -1;
        goto out;
    }

    iresp = (struct isula_remove_response *)util_common_calloc_s(sizeof(struct isula_remove_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    nret = get_isula_image_connect_config(&conf);
    if (nret != 0) {
        ret = -1;
        goto out;
    }

    INFO("Send remove rootfs GRPC request");
    nret = im_ops->remove(ireq, iresp, &conf);
    if (nret != 0) {
        if (iresp->errmsg != NULL) {
            if (strstr(iresp->errmsg, CONTAINER_NOT_KNOWN_ERR) != NULL) {
                DEBUG("Container %s may already removed", name_id);
                goto out;
            }
            ERROR("Remove rootfs %s failed: %s", name_id, iresp->errmsg);
        } else {
            ERROR("Failed to remove rootfs of %s", name_id);
        }
        ret = -1;
    }

out:
    free_isula_remove_request(ireq);
    free_isula_remove_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
