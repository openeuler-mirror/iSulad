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
* Author: liuhao
* Create: 2020-03-24
* Description: isula storage metadata operator implement
*******************************************************************************/
#include "isula_storage_metadata.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "isula_libutils/log.h"

int isula_do_storage_metadata(char *id, im_storage_metadata_response *resp)
{
    int ret = 0;
    int nret = -1;
    struct isula_storage_metadata_request ireq;
    struct isula_storage_metadata_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    if (resp == NULL || id == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Failed to init isula server grpc client");
        return -1;
    }
    if (im_ops->storage_metadata == NULL) {
        ERROR("Umimplement get storage metadata operator");
        return -1;
    }

    iresp = util_common_calloc_s(sizeof(struct isula_storage_metadata_response));
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

    ireq.container_id = id;
    nret = im_ops->storage_metadata(&ireq, iresp, &conf);
    if (nret != 0) {
        ERROR("Failed to get storage metadata with error: %s", iresp->errmsg);
        isulad_set_error_message("Failed to get storage metadata with error: %s", iresp->errmsg);
        ret = -1;
        goto out;
    }
    resp->metadata = iresp->metadata;
    iresp->metadata = NULL;
    resp->name = util_strdup_s(iresp->name);
    resp->errmsg = util_strdup_s(iresp->errmsg);

out:
    free_isula_storage_metadata_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}

