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
* Create: 2019-09-05
* Description: isula containers list operator implement
*******************************************************************************/
#include "isula_containers_list.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "log.h"

int isula_list_containers(json_map_string_bool **containers)
{
    struct isula_containers_list_request ireq = { 0 };
    struct isula_containers_list_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;
    int ret = -1;

    if (containers == NULL) {
        return ret;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return ret;
    }
    if (im_ops->containers_list == NULL) {
        ERROR("Umimplement containers list operator");
        return ret;
    }

    iresp = (struct isula_containers_list_response *)util_common_calloc_s(
                sizeof(struct isula_containers_list_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = im_ops->containers_list(&ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("List containers failed: %s", iresp != NULL ? iresp->errmsg : "null");
        goto out;
    }

    *containers = iresp->containers;
    iresp->containers = NULL;
out:
    free_isula_containers_list_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
