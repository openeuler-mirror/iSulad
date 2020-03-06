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
* Description: isula image status operator implement
*******************************************************************************/
#include "isula_image_status.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "log.h"

static int generate_isula_status_request(const char *image_name, struct isula_status_request **ireq)
{
    struct isula_status_request *tmp_req = NULL;

    if (image_name == NULL) {
        ERROR("Image name is required");
        return -1;
    }
    tmp_req = (struct isula_status_request *)util_common_calloc_s(sizeof(struct isula_status_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    tmp_req->image = (struct image_spec *)util_common_calloc_s(sizeof(struct image_spec));
    if (tmp_req->image == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    tmp_req->image->image = util_strdup_s(image_name);

    *ireq = tmp_req;
    return 0;

err_out:
    free_isula_status_request(tmp_req);
    return -1;
}

static void pack_imagetool_image(struct image_metadata *data, imagetool_image **image)
{
    parser_error err = NULL;
    imagetool_image *tmp_img = NULL;

    if (data == NULL) {
        return;
    }
    tmp_img = (imagetool_image *)util_common_calloc_s(sizeof(imagetool_image));
    if (tmp_img == NULL) {
        ERROR("Out of memory");
        return;
    }

    tmp_img->uid = (imagetool_image_uid *)util_common_calloc_s(sizeof(imagetool_image_uid));
    if (tmp_img->uid == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    tmp_img->uid->value = data->uid;
    data->uid = 0;
    tmp_img->id = data->id;
    data->id = NULL;
    tmp_img->repo_tags = data->repo_tags;
    data->repo_tags = NULL;
    tmp_img->repo_tags_len = data->repo_tags_len;
    data->repo_tags_len = 0;
    tmp_img->repo_digests = data->repo_digests;
    data->repo_digests = NULL;
    tmp_img->repo_digests_len = data->repo_digests_len;
    data->repo_digests_len = 0;
    tmp_img->size = data->size;
    data->size = 0;
    tmp_img->username = data->username;
    data->username = NULL;

    tmp_img->created = data->created;
    data->created = NULL;
    tmp_img->loaded = data->loaded;
    data->loaded = NULL;

    // parse oci image spec
    tmp_img->spec = oci_image_spec_parse_data(data->oci_spec, NULL, &err);
    if (tmp_img->spec == NULL) {
        ERROR("Parse oci image spec failed: %s", err);
        goto err_out;
    }

    free(err);
    *image = tmp_img;
    return;

err_out:
    free(err);
    free_imagetool_image(tmp_img);
}

imagetool_image *isula_image_get_image_info_by_name(const char *image_name)
{
    struct isula_status_request *ireq = NULL;
    struct isula_status_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;
    imagetool_image *result = NULL;
    int ret = -1;

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return NULL;
    }
    if (im_ops->status == NULL) {
        ERROR("Umimplement status operator");
        return NULL;
    }

    ret = generate_isula_status_request(image_name, &ireq);
    if (ret != 0) {
        goto out;
    }

    iresp = (struct isula_status_response *)util_common_calloc_s(sizeof(struct isula_status_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    ret = im_ops->status(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Get status of image %s failed: %s", image_name, iresp != NULL ? iresp->errmsg : "null");
        goto out;
    }

    pack_imagetool_image(iresp->image, &result);
out:
    free_isula_status_request(ireq);
    free_isula_status_response(iresp);
    free_client_connect_config_value(&conf);
    return result;
}
