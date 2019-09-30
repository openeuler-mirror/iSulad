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
 * Description: provide oci image status functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "oci_image_status.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "isula_imtool_interface.h"

static bool do_status(oci_image_status_request *request,
                      imagetool_image_status **image)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    parser_error err = NULL;

    command_ret = util_exec_cmd(execute_status_image, request, NULL, &stdout_buffer,
                                &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to status image with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to status image with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec status image command");
            lcrd_set_error_message("Failed to exec status image command");
        }
        goto free_out;
    }

    if (stdout_buffer == NULL) {
        ERROR("Failed to status image becase can not get stdoutput");
        lcrd_set_error_message("Failed to status image becase can not get stdoutput");
        goto free_out;
    }

    *image = imagetool_image_status_parse_data(stdout_buffer, NULL, &err);
    if (*image == NULL) {
        ERROR("Failed to parse output json:%s", err);
        lcrd_set_error_message("Failed to parse output json:%s", err);
        goto free_out;
    }

    ret = true;

free_out:
    free(err);
    free(stderr_buffer);
    free(stdout_buffer);
    return ret;
}


static int do_status_oci_image(oci_image_status_request *request,
                               oci_image_status_response **response)
{
    int ret = 0;
    imagetool_image_status *image = NULL;
    char *image_ref = NULL;

    image_ref = request->image.image;

    *response = util_common_calloc_s(sizeof(oci_image_status_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (image_ref == NULL) {
        ERROR("Inspect image requires image ref");
        lcrd_set_error_message("Inspect image requires image ref");
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: inspecting image}", image_ref);

    if (!do_status(request, &image)) {
        ERROR("Failed to status image: %s", image_ref);
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: inspected image}", image_ref);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }

    (*response)->image_info = image;

    return ret;
}

void free_oci_image_status_request(oci_image_status_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->image.image);
    ptr->image.image = NULL;

    free(ptr);
}

void free_oci_image_status_response(oci_image_status_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free_imagetool_image_status(ptr->image_info);
    ptr->image_info = NULL;
    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

imagetool_image *oci_image_get_image_info_by_name(const char *image_name)
{
    oci_image_status_request *request = NULL;
    oci_image_status_response *response = NULL;
    imagetool_image *image = NULL;

    if (image_name == NULL) {
        ERROR("Empty image name");
        return NULL;
    }

    request = (oci_image_status_request *)util_common_calloc_s(sizeof(*request));
    if (request == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    request->image.image = util_strdup_s(image_name);

    if (do_status_oci_image(request, &response)) {
        goto cleanup;
    }

    if (response->image_info != NULL) {
        image = response->image_info->image;
        response->image_info->image = NULL;
    }

cleanup:
    free_oci_image_status_request(request);
    free_oci_image_status_response(response);
    return image;
}
