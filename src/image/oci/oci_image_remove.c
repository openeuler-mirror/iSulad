/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide oci image remove functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "utils.h"
#include "log.h"
#include "image.h"
#include "oci_images_store.h"
#include "isula_imtool_interface.h"
#include "oci_image.h"

#define IMAGE_NOT_KNOWN_ERR "image not known"

int oci_remove_image(im_remove_request *request)
{
    int ret = 0;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    char *tmp = NULL;
    oci_image_t *image_info = NULL;
    bool locked = false;

    if (request->image.image == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    tmp = oci_resolve_image_name(request->image.image);
    if (tmp == NULL) {
        ERROR("Failed to resolve image name");
        ret = -1;
        goto free_out;
    }

    image_info = oci_images_store_get(tmp);
    if (image_info == NULL) {
        INFO("No such image exist %s", tmp);
        ret = 0;
        goto free_out;
    }

    /* isulad_kit does not support concurrent delete tags of the same image,
     * so we should make sure we delete tags one by one. */
    oci_image_lock(image_info);
    locked = true;

    free(request->image.image);
    request->image.image = util_strdup_s(tmp);

    command_ret = util_exec_cmd(execute_remove_image, request, NULL, &stdout_buffer, &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            if (strstr(stderr_buffer, IMAGE_NOT_KNOWN_ERR) != NULL) {
                DEBUG("Image %s may already removed", request->image.image);
                ret = 0;
                goto clean_memory;
            }
            ERROR("Failed to remove image with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to remove image with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec remove image command");
            lcrd_set_error_message("Failed to exec remove image command");
        }
        ret = -1;
        goto free_out;
    }

clean_memory:
    ret = remove_oci_image_from_memory(tmp);
    if (ret != 0) {
        ERROR("Failed to remove image %s from memory", tmp);
        ret = -1;
        goto free_out;
    }

free_out:
    if (locked) {
        oci_image_unlock(image_info);
    }
    free(tmp);
    free(stderr_buffer);
    free(stdout_buffer);
    oci_image_unref(image_info);
    return ret;
}

