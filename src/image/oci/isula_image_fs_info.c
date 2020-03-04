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
* Description: isula image fs info operator implement
*******************************************************************************/
#include "isula_image_fs_info.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "log.h"

static int fs_usage_to_json_elem(const struct filesystem_usage *fusage,
                                 imagetool_fs_info_image_filesystems_element **jelem)
{
    imagetool_fs_info_image_filesystems_element *tmp_elem = NULL;

    tmp_elem = (imagetool_fs_info_image_filesystems_element *)util_common_calloc_s(
                   sizeof(imagetool_fs_info_image_filesystems_element));
    if (tmp_elem == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    tmp_elem->timestamp = fusage->timestamp;
    tmp_elem->fs_id = (imagetool_fs_info_image_filesystems_fs_id *)util_common_calloc_s(
                          sizeof(imagetool_fs_info_image_filesystems_fs_id));
    if (tmp_elem->fs_id == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    tmp_elem->fs_id->mountpoint = util_strdup_s(fusage->uuid);

    tmp_elem->used_bytes = (imagetool_fs_info_image_filesystems_used_bytes *)util_common_calloc_s(
                               sizeof(imagetool_fs_info_image_filesystems_used_bytes));
    if (tmp_elem->used_bytes == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    tmp_elem->used_bytes->value = *(fusage->used_bytes);

    tmp_elem->inodes_used = (imagetool_fs_info_image_filesystems_inodes_used *)util_common_calloc_s(
                                sizeof(imagetool_fs_info_image_filesystems_inodes_used));
    if (tmp_elem->inodes_used == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    tmp_elem->inodes_used->value = *(fusage->inodes_used);

    *jelem = tmp_elem;
    return 0;
err_out:
    free_imagetool_fs_info_image_filesystems_element(tmp_elem);
    return -1;
}

static int pack_im_response(const struct isula_image_fs_info_response *iresp, im_fs_info_response *resp)
{
    size_t i = 0;
    imagetool_fs_info *info = NULL;

    if (iresp->image_filesystems_len == 0) {
        return 0;
    }

    info = (imagetool_fs_info *)util_common_calloc_s(sizeof(imagetool_fs_info));
    if (info == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    info->image_filesystems = (imagetool_fs_info_image_filesystems_element **)util_smart_calloc_s(
                                  sizeof(imagetool_fs_info_image_filesystems_element *), iresp->image_filesystems_len);
    if (info->image_filesystems == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    for (i = 0; i < iresp->image_filesystems_len; i++) {
        if (fs_usage_to_json_elem(iresp->image_filesystems[i], &(info->image_filesystems[i])) != 0) {
            goto err_out;
        }
        (info->image_filesystems_len)++;
    }

    resp->fs_info = info;
    resp->errmsg = util_strdup_s(iresp->errmsg);
    return 0;

err_out:
    free_imagetool_fs_info(info);
    return -1;
}

int isula_image_fs_info(im_fs_info_response *resp)
{
    int ret = -1;
    struct isula_image_fs_info_request ireq = {0};
    struct isula_image_fs_info_response *iresp = NULL;
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
    if (im_ops->image_fs_info == NULL) {
        ERROR("Umimplement image fs info operator");
        return -1;
    }

    iresp = (struct isula_image_fs_info_response *)util_common_calloc_s(sizeof(struct isula_image_fs_info_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    ret = im_ops->image_fs_info(&ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Failed to get image fs info with error: %s", iresp->errmsg);
        isulad_set_error_message("Failed to get image fs info with error: %s", iresp->errmsg);
        goto out;
    }
    ret = pack_im_response(iresp, resp);

out:
    free_isula_image_fs_info_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
