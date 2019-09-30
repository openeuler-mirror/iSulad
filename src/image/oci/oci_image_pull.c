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
 * Description: provide oci image pull functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "oci_images_store.h"
#include "oci_image_pull.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "isula_imtool_interface.h"
#include "oci_image.h"
#include "imagetool_auth_input.h"
#include "oci_auth.h"

static bool do_pull(image_pull_request *request, char **image_ref)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    char *stdin_buffer = NULL;

    stdin_buffer = pack_input_auth_string(&request->auth);
    if (stdin_buffer == NULL) {
        ERROR("Failed to generate image auth info");
        lcrd_set_error_message("Failed to generate image auth info");
        goto free_out;
    }

    command_ret = util_exec_cmd(execute_pull_image, request, stdin_buffer, &stdout_buffer,
                                &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to pull image with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to pull image with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec pull image command");
            lcrd_set_error_message("Failed to exec pull image command");
        }
        goto free_out;
    }

    if (stdout_buffer != NULL) {
        INFO("Pulled image with ref: %s", stdout_buffer);
        *image_ref = util_strdup_s(stdout_buffer);
    } else {
        ERROR("Failed to pull image ref becase can't get image ref");
        lcrd_set_error_message("Failed to pull image ref becase can't get image ref");
        goto free_out;
    }

    ret = true;

free_out:
    free_sensitive_string(stdin_buffer);
    free(stderr_buffer);
    free(stdout_buffer);
    return ret;
}

int pull_image(image_pull_request *request, image_pull_response **response)
{
    int ret = 0;
    char *tmp = NULL;
    char *image_ref = NULL;
    char *normalized_ref = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (request->image.image == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(image_pull_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    /* Max length should include the ":latest" which may not provided when
     * pulling image, so we need to normalize image name before checking it. */
    normalized_ref = oci_normalize_image_name(request->image.image);
    if (!util_valid_image_name(normalized_ref)) {
        ERROR("Invalid image name %s", normalized_ref);
        ret = -1;
        lcrd_try_set_error_message("Invalid image name:%s", normalized_ref);
        goto pack_response;
    }

    tmp = oci_resolve_image_name(request->image.image);
    if (tmp == NULL) {
        ERROR("Failed to resolve image name");
        ret = -1;
        goto pack_response;
    }
    free(request->image.image);
    request->image.image = tmp;

    set_log_prefix(request->image.image);

    EVENT("Event: {Object: %s, Type: Pulling}", request->image.image);

    if (!do_pull(request, &image_ref)) {
        ERROR("Failed to pull image");
        ret = -1;
        goto pack_response;
    }

    ret = register_new_oci_image_into_memory(request->image.image);
    if (ret != 0) {
        ERROR("Failed to register new image to images store");
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: Pulled}", request->image.image);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }
    if (image_ref != NULL) {
        (*response)->image_ref = util_strdup_s(image_ref);
        free(image_ref);
    }

    free(normalized_ref);

    free_log_prefix();
    return ret;
}

void free_image_pull_request(image_pull_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->image.image);
    ptr->image.image = NULL;
    free_sensitive_string(ptr->auth.username);
    ptr->auth.username = NULL;
    free_sensitive_string(ptr->auth.password);
    ptr->auth.password = NULL;
    free_sensitive_string(ptr->auth.auth);
    ptr->auth.auth = NULL;
    free_sensitive_string(ptr->auth.server_address);
    ptr->auth.server_address = NULL;
    free_sensitive_string(ptr->auth.identity_token);
    ptr->auth.identity_token = NULL;
    free_sensitive_string(ptr->auth.registry_token);
    ptr->auth.registry_token = NULL;

    free(ptr);
}

void free_image_pull_response(image_pull_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->image_ref);
    ptr->image_ref = NULL;
    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

