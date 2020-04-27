/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: isula image pull operator implement
*******************************************************************************/
#include "isula_image_pull.h"

#include "isula_libutils/log.h"
#include "utils.h"
#include "oci_images_store.h"
#include "oci_common_operators.h"
#include "registry.h"

int isula_pull_image(const im_pull_request *request, im_pull_response **response)
{
    int ret = -1;
    char *normalized = NULL;
    registry_pull_options *options = NULL;

    if (request == NULL || request->image == NULL || response == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    options = (registry_pull_options *)util_common_calloc_s(sizeof(registry_pull_options));
    if (options == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    options->image_name = util_strdup_s(request->image);
    options->dest_image_name = util_strdup_s(request->image);

    ret = registry_pull(options);
    if (ret != 0) {
        ERROR("registry pull failed");
        goto err_out;
    }

    *response = (im_pull_response *)util_common_calloc_s(sizeof(im_pull_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    (*response)->image_ref = util_strdup_s(request->image);

    normalized = oci_normalize_image_name(request->image);
    if (normalized == NULL) {
        ret = -1;
        ERROR("Normalize image name %s failed", request->image);
        goto err_out;
    }

    ret = register_new_oci_image_into_memory(normalized);
    if (ret != 0) {
        ERROR("Register image %s into store failed", normalized);
        goto err_out;
    }

    goto out;
err_out:
    free_im_pull_response(*response);
    *response = NULL;
    ret = -1;
out:
    free_registry_pull_options(options);
    free(normalized);
    return ret;
}
