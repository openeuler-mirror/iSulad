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
* Description: isula image rootfs umount operator implement
*******************************************************************************/
#include "isula_rootfs_umount.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "log.h"

static int generate_isula_umount_request(const char *name_id, bool force, struct isula_umount_request **ireq)
{
    struct isula_umount_request *tmp_req = NULL;

    if (name_id == NULL) {
        ERROR("Invalid container id or name");
        return -1;
    }
    tmp_req = (struct isula_umount_request *)util_common_calloc_s(sizeof(struct isula_umount_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    tmp_req->name_id = util_strdup_s(name_id);

    tmp_req->force = force;

    *ireq = tmp_req;
    return 0;
}

static bool is_container_nonexist_error(const struct isula_umount_response *iresp)
{
#define CONTAINER_NOT_KNOWN_ERR "container not known"
    if (iresp == NULL || iresp->errmsg == NULL) {
        return false;
    }

    if (strstr(iresp->errmsg, CONTAINER_NOT_KNOWN_ERR) != NULL) {
        DEBUG("Container may already removed");
        return true;
    }

    return false;
}

int isula_rootfs_umount(const char *name_id, bool force)
{
    int ret = 0;
    int nret = -1;
    struct isula_umount_request *ireq = NULL;
    struct isula_umount_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->umount == NULL) {
        ERROR("Umimplement umount operator");
        return -1;
    }

    nret = generate_isula_umount_request(name_id, force, &ireq);
    if (nret != 0) {
        ret = -1;
        goto out;
    }

    iresp = (struct isula_umount_response *)util_common_calloc_s(sizeof(struct isula_umount_response));
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

    INFO("Send umount rootfs GRPC request");
    nret = im_ops->umount(ireq, iresp, &conf);
    if (nret != 0 && !is_container_nonexist_error(iresp)) {
        ERROR("Remove rootfs %s failed: %s", name_id, iresp != NULL ? iresp->errmsg : "null");
        ret = -1;
    }

out:
    free_isula_umount_request(ireq);
    free_isula_umount_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
