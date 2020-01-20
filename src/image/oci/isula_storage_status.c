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
* Description: isula storage status operator implement
*******************************************************************************/
#include "isula_storage_status.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "log.h"

// format: [status xx: val]
static int get_graphdriver_status_line_value(const char *line, char **start, char **end)
{
    char *pstart = NULL;
    char *pend = NULL;

    pstart = strchr(line, ':');
    if (pstart == NULL) {
        ERROR("Invalid output: %s", line);
        return -1;
    }
    pstart++;
    if (*pstart != ' ') {
        ERROR("Invalid output: %s", line);
        return -1;
    }
    pstart++;

    pend = strchr(pstart, '\n');
    if (pend == NULL) {
        ERROR("Invalid output: %s", pstart);
        return -1;
    }
    *pend++ = '\0';

    *start = pstart;
    *end = pend;
    return 0;
}

static int pack_im_response(const struct isula_storage_status_response *iresp, im_storage_status_response *resp)
{
    char *pstart = NULL;
    char *pend = NULL;

    if (iresp->status == NULL) {
        ERROR("Storage status response status NULL");
        isulad_set_error_message("Storage status response NULL");
        return -1;
    }

    resp->status = util_strdup_s(iresp->status);

    // Backing Filesystem: extfs
    if (get_graphdriver_status_line_value(iresp->status, &pstart, &pend) != 0) {
        ERROR("Get backing filesystem from status failed. status:%s", iresp->status);
        isulad_set_error_message("Get backing filesystem from status failed");
        return -1;
    }
    resp->backing_fs = util_strdup_s(pstart);

    return 0;
}

int isula_do_storage_status(im_storage_status_response *resp)
{
    int ret = 0;
    int nret = -1;
    struct isula_storage_status_request ireq = {0};
    struct isula_storage_status_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    if (resp == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->storage_status == NULL) {
        ERROR("Umimplement get storage status operator");
        return -1;
    }

    iresp = (struct isula_storage_status_response *)util_common_calloc_s(sizeof(struct isula_storage_status_response));
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

    nret = im_ops->storage_status(&ireq, iresp, &conf);
    if (nret != 0) {
        ERROR("Failed to get storage status with error: %s", iresp->errmsg);
        isulad_set_error_message("Failed to get storage status with error: %s", iresp->errmsg);
        ret = -1;
        goto out;
    }
    ret = pack_im_response(iresp, resp);
    if (ret != 0) {
        goto out;
    }

out:
    free_isula_storage_status_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}

