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
* Description: isula images list operator implement
*******************************************************************************/
#include "isula_images_list.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "log.h"

static int generate_isula_list_request(const im_list_request *req, struct isula_list_request **ireq)
{
    struct isula_list_request *tmp_req = NULL;

    if (req == NULL) {
        return 0;
    }
    tmp_req = (struct isula_list_request *)util_common_calloc_s(sizeof(struct isula_list_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    tmp_req->filter = util_strdup_s(req->filter.image.image);
    tmp_req->check = req->check;

    *ireq = tmp_req;
    return 0;
}

/* user move to decrease memory allocate */
static int pack_imagetool_image(struct image_metadata *data, imagetool_image **image)
{
    parser_error err = NULL;
    imagetool_image *tmp_img = NULL;

    if (data == NULL) {
        return -1;
    }
    tmp_img = (imagetool_image *)util_common_calloc_s(sizeof(imagetool_image));
    if (tmp_img == NULL) {
        ERROR("Out of memory");
        return -1;
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
    return 0;

err_out:
    free(err);
    free_imagetool_image(tmp_img);
    return -1;
}

static int pack_imagetool_images_list(const struct isula_list_response *resp, imagetool_images_list **images)
{
    int ret = 0;
    size_t i = 0;
    imagetool_images_list *tmp_list = NULL;

    if (resp == NULL) {
        ret = -1;
        goto err_out;
    }
    tmp_list = (imagetool_images_list *)util_common_calloc_s(sizeof(imagetool_images_list));
    if (tmp_list == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto err_out;
    }
    if (resp->images_len == 0) {
        DEBUG("Get number of images is 0");
        goto out;
    }
    tmp_list->images = (imagetool_image **)util_common_calloc_s(sizeof(imagetool_image *) * resp->images_len);
    if (tmp_list->images == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto err_out;
    }
    for (; i < resp->images_len; i++) {
        if (pack_imagetool_image(resp->images[i], &(tmp_list->images[i])) != 0) {
            break;
        }
        tmp_list->images_len++;
    }

    goto out;

err_out:
    free(tmp_list);
    tmp_list = NULL;
out:
    *images = tmp_list;
    return ret;
}

int isula_list_images(const im_list_request *request, imagetool_images_list **images)
{
    struct isula_list_request *ireq = NULL;
    struct isula_list_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;
    int ret = -1;

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return ret;
    }
    if (im_ops->list == NULL) {
        ERROR("Umimplement list operator");
        return ret;
    }

    ret = generate_isula_list_request(request, &ireq);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    iresp = (struct isula_list_response *)util_common_calloc_s(sizeof(struct isula_list_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = im_ops->list(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("List images failed: %s", iresp != NULL ? iresp->errmsg : "null");
        goto out;
    }

    if (pack_imagetool_images_list(iresp, images) != 0) {
        ERROR("Failed to pack images list");
        ret = -1;
        goto out;
    }
out:
    free_isula_list_request(ireq);
    free_isula_list_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
