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
* Author: wangfengtu
* Create: 2020-05-26
* Description: isula image import operator implement
*******************************************************************************/
#include "isula_import.h"
#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "libisulad.h"
#include "utils_verify.h"
#include "isula_libutils/log.h"

static int generate_isula_import_request(const char *file, const char *tag, struct isula_import_request **ireq)
{
    struct isula_import_request *tmp_req = NULL;

    tmp_req = (struct isula_import_request *)util_common_calloc_s(sizeof(struct isula_import_request));
    if (tmp_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    tmp_req->file = util_strdup_s(file);
    tmp_req->tag = util_strdup_s(tag);

    *ireq = tmp_req;
    return 0;
}

static int is_valid_arguments(const char *file, const char *tag, char **id)
{
    if (file == NULL) {
        isulad_set_error_message("Import image requires input file path");
        return -1;
    }
    if (tag == NULL || !util_valid_tag(tag)) {
        isulad_try_set_error_message("Invalid tag:%s", tag);
        return -1;
    }

    if (id == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    return 0;
}

int isula_do_import(const char *file, const char *tag, char **id)
{
    int ret = -1;
    struct isula_import_request *ireq = NULL;
    struct isula_import_response *iresp = NULL;
    client_connect_config_t conf = { 0 };
    isula_image_ops *im_ops = NULL;

    if (is_valid_arguments(file, tag, id) != 0) {
        return -1;
    }

    im_ops = get_isula_image_ops();
    if (im_ops == NULL) {
        ERROR("Don't init isula server grpc client");
        return -1;
    }
    if (im_ops->import == NULL) {
        ERROR("Umimplement import operator");
        return -1;
    }

    ret = generate_isula_import_request(file, tag, &ireq);
    if (ret != 0) {
        goto out;
    }

    iresp = (struct isula_import_response *)util_common_calloc_s(sizeof(struct isula_import_response));
    if (iresp == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_isula_image_connect_config(&conf);
    if (ret != 0) {
        goto out;
    }

    ret = im_ops->import(ireq, iresp, &conf);
    if (ret != 0) {
        ERROR("Import image %s failed: %s", file, iresp->errmsg);
        isulad_set_error_message(iresp->errmsg);
        goto out;
    }

    *id = util_strdup_s(iresp->id);

out:
    free_isula_import_request(ireq);
    free_isula_import_response(iresp);
    free_client_connect_config_value(&conf);
    return ret;
}
