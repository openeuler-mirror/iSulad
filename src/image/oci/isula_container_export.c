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
* Description: isula container export operator implement
*******************************************************************************/
#include "isula_container_export.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "libisulad.h"
#include "log.h"

static struct isula_export_request *generate_isula_export_request(const char *name_id, const char *out_file,
                                                                  uint32_t uid, uint32_t gid,
                                                                  uint32_t offset)
{
    struct isula_export_request *ret = NULL;

    ret = (struct isula_export_request *)util_common_calloc_s(sizeof(struct isula_export_request));
    if (ret == NULL) {
        ERROR("Out of memory");
        return ret;
    }
    ret->name_id = util_strdup_s(name_id);
    ret->output = util_strdup_s(out_file);
    ret->uid = uid;
    ret->gid = gid;
    ret->offset = offset;

    return ret;
}

static int is_valid_arguments(const char *name_id, const char *out_file)
{
    if (name_id == NULL) {
        isulad_set_error_message("Export rootfs requires container name");
        return -1;
    }
    if (out_file == NULL) {
        isulad_set_error_message("Export rootfs requires output file path");
        return -1;
    }
    return 0;
}

int isula_container_export(const char *name_id, const char *out_file, uint32_t uid, uint32_t gid, uint32_t offset)
{
    int ret = -1;
    struct isula_export_request *ireq = NULL;
    struct isula_export_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    if (is_valid_arguments(name_id, out_file) != 0) {
        ERROR("Invalid arguments");
        return -1;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }

    if (im_ops->container_export == NULL) {
        ERROR("Umimplement container_export operator");
        return -1;
    }

    ireq = generate_isula_export_request(name_id, out_file, uid, gid, offset);
    if (ireq == NULL) {
        goto out;
    }

    iresp = (struct isula_export_response *)util_common_calloc_s(sizeof(struct isula_export_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    ret = im_ops->container_export(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Failed to export rootfs : %s", iresp->errmsg);
        isulad_set_error_message("Failed to export rootfs with error: %s", iresp->errmsg);
    }

out:
    free_isula_export_request(ireq);
    free_isula_export_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
