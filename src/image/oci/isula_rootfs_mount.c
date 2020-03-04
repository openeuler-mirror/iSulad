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
* Description: isula image rootfs mount operator implement
*******************************************************************************/
#include "isula_rootfs_mount.h"

#include "isula_image_connect.h"
#include "connect.h"
#include "isula_helper.h"
#include "utils.h"
#include "log.h"

static int generate_isula_mount_request(const char *name_id, struct isula_mount_request **ireq)
{
    struct isula_mount_request *tmp_req = NULL;

    if (name_id == NULL) {
        ERROR("Invalid container id or name");
        return -1;
    }
    tmp_req = (struct isula_mount_request *)util_common_calloc_s(sizeof(struct isula_mount_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    tmp_req->name_id = util_strdup_s(name_id);

    *ireq = tmp_req;
    return 0;
}

int isula_rootfs_mount(const char *name_id)
{
    int ret = -1;
    struct isula_mount_request *ireq = NULL;
    struct isula_mount_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->mount == NULL) {
        ERROR("Umimplement mount operator");
        return -1;
    }

    ret = generate_isula_mount_request(name_id, &ireq);
    if (ret != 0) {
        goto out;
    }

    iresp = (struct isula_mount_response *)util_common_calloc_s(sizeof(struct isula_mount_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    INFO("Send mount rootfs GRPC request");
    ret = im_ops->mount(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Remove rootfs %s failed: %s", name_id, iresp != NULL ? iresp->errmsg : "null");
    }

out:
    free_isula_mount_request(ireq);
    free_isula_mount_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}

