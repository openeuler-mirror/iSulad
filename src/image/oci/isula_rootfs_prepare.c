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
* Description: isula image prepare operator implement
*******************************************************************************/
#include "isula_rootfs_prepare.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "isulad_config.h"
#include "utils.h"
#include "log.h"

static int generate_isula_prepare_request(const char *container_id, const char *image_name,
                                          const json_map_string_string *storage_opt,
                                          struct isula_prepare_request **ireq)
{
    struct isula_prepare_request *tmp_req = NULL;

    if (ireq == NULL) {
        return -1;
    }

    tmp_req = (struct isula_prepare_request *)util_common_calloc_s(sizeof(struct isula_prepare_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (map_to_key_value_string(storage_opt, &(tmp_req->storage_opts), &(tmp_req->storage_opts_len)) != 0) {
        ERROR("Map to string array failed");
        goto err_out;
    }
    tmp_req->id = util_strdup_s(container_id);
    tmp_req->name = util_strdup_s(container_id);
    tmp_req->image = util_strdup_s(image_name);

    *ireq = tmp_req;
    return 0;
err_out:
    free_isula_prepare_request(tmp_req);
    return -1;
}

static int parse_image_conf_from_json_str(const char *image_conf_str, oci_image_spec **spec)
{
    parser_error err = NULL;
    int ret = 0;

    if (spec == NULL) {
        return 0;
    }
    *spec = oci_image_spec_parse_data(image_conf_str, NULL, &err);
    if (*spec == NULL) {
        ERROR("Failed to parse image conf: %s", err);
        isulad_set_error_message("Failed to parse image conf");
        ret = -1;
    }

    free(err);
    return ret;
}

static int dealwith_result(int result, struct isula_prepare_response *iresp, char **real_rootfs, oci_image_spec **spec)
{
    int ret = result;

    if (result != 0) {
        if (iresp->errmsg != NULL) {
            ERROR("Failed to prepare rootfs with error: %s", iresp->errmsg);
            isulad_set_error_message("Failed to prepare rootfs with error: %s", iresp->errmsg);
        } else {
            ERROR("Failed to prepare rootfs");
            isulad_set_error_message("Failed to prepare rootfs");
        }
    } else {
        *real_rootfs = iresp->mount_point;
        iresp->mount_point = NULL;
        ret = parse_image_conf_from_json_str(iresp->image_conf, spec);
    }

    return ret;
}

int isula_rootfs_prepare_and_get_image_conf(const char *container_id, const char *image_name,
                                            const json_map_string_string *storage_opt,
                                            char **real_rootfs, oci_image_spec **spec)
{
    int ret = -1;
    struct isula_prepare_request *ireq = NULL;
    struct isula_prepare_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    if (container_id == NULL || image_name == NULL || real_rootfs == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->prepare == NULL) {
        ERROR("Umimplement prepare operator");
        return -1;
    }

    iresp = (struct isula_prepare_response *)util_common_calloc_s(sizeof(struct isula_prepare_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto err_out;
    }

    ret = generate_isula_prepare_request(container_id, image_name, storage_opt, &ireq);
    if (ret != 0) {
        goto err_out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto err_out;
    }

    INFO("Send prepare rootfs GRPC request");
    ret = im_ops->prepare(ireq, iresp, &conf);

    ret = dealwith_result(ret, iresp, real_rootfs, spec);

err_out:
    free_client_connect_config_value(&conf);
    free_isula_prepare_request(ireq);
    free_isula_prepare_response(iresp);
    return ret;
}
