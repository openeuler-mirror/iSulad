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
* Description: isula container fs usage operator implement
*******************************************************************************/
#include "isula_container_fs_usage.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "libisulad.h"
#include "log.h"

static int generate_isula_container_fs_usage_request(const char *name_id,
                                                     struct isula_container_fs_usage_request **ireq)
{
    struct isula_container_fs_usage_request *tmp_req = NULL;

    tmp_req = (struct isula_container_fs_usage_request *)util_common_calloc_s(
                  sizeof(struct isula_container_fs_usage_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    tmp_req->name_id = util_strdup_s(name_id);

    *ireq = tmp_req;
    return 0;
}

static int is_valid_arguments(const char *name_id, char **usages)
{
    if (usages == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }
    if (name_id == NULL) {
        ERROR("Invalid container id or name");
        return -1;
    }
    return 0;
}

int isula_container_fs_usage(const char *name_id, char **usages)
{
    int ret = -1;
    struct isula_container_fs_usage_request *ireq = NULL;
    struct isula_container_fs_usage_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    if (is_valid_arguments(name_id, usages) != 0) {
        return -1;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }

    if (im_ops->container_fs_usage == NULL) {
        ERROR("Umimplement container fs usage operator");
        return -1;
    }

    ret = generate_isula_container_fs_usage_request(name_id, &ireq);
    if (ret != 0) {
        goto out;
    }

    iresp = (struct isula_container_fs_usage_response *)util_common_calloc_s(sizeof(struct
                                                                                    isula_container_fs_usage_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    ret = im_ops->container_fs_usage(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Get container %s fs usage failed: %s", name_id, iresp->errmsg);
        isulad_set_error_message("Failed to container fs info with error: %s", iresp->errmsg);
        goto out;
    }
    *usages = iresp->usage;
    iresp->usage = NULL;

out:
    free_isula_container_fs_usage_request(ireq);
    free_isula_container_fs_usage_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
