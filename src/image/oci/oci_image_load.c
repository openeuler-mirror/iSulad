/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2019-04-09
 * Description: provide oci load image functions
 ******************************************************************************/

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "oci_image_load.h"
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "isula_imtool_interface.h"
#include "oci_images_store.h"
#include "image.h"

const int stdout_buffer_max_size = 10 * SIZE_MB; /* 10M */

static char *get_ref_from_stdout_buffer(const char *stdout_buffer)
{
    char *ref = NULL;
    size_t len = 0;
    char *key_word = "Loaded image: ";

    ref = strstr(stdout_buffer, key_word);
    if (ref == NULL) {
        return NULL;
    }

    /* skip key word */
    ref += strlen(key_word);

    /* +1 for '\n' and +1 for terminator */
    len = strnlen(ref, (size_t)(MAX_IMAGE_REF_LEN + 2));
    if (len == 0 || len > MAX_IMAGE_REF_LEN) {
        return NULL;
    }

    /* strip '\n' */
    ref[len - 1] = 0;

    return util_strdup_s(ref);
}

static bool do_load(im_load_request *request, char **ref)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    char *tmp_stdout_buffer = NULL;

    command_ret = util_exec_cmd(execute_load_image, request, NULL, &stdout_buffer, &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to load image with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to load image with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec load image command");
            lcrd_set_error_message("Failed to exec load image command");
        }
        goto free_out;
    }

    if (stdout_buffer == NULL) {
        ERROR("Failed to load image because can not get stdoutput");
        lcrd_set_error_message("Failed to load image because can not get stdoutput");
        goto free_out;
    }

    if (strnlen(stdout_buffer, (size_t)(stdout_buffer_max_size + 1)) > (size_t)stdout_buffer_max_size) {
        ERROR("Failed to load image because stdoutput exceeded max size");
        lcrd_set_error_message("Failed to load image because stdoutput exceeded max size");
        goto free_out;
    }

    /* get_ref_from_stdout_buffer will modify stdout_buffer, get a copy to do this because
       we want to print original buffer if get reference failed. */
    tmp_stdout_buffer = util_strdup_s(stdout_buffer);
    *ref = get_ref_from_stdout_buffer(tmp_stdout_buffer);
    if (*ref == NULL) {
        ERROR("Failed to load image because cann't get image reference from stdout buffer."
              "stdout buffer is [%s]",
              stdout_buffer);
        lcrd_set_error_message("Failed to load image because cann't get image reference from stdout buffer");
        goto free_out;
    }

    ret = true;

free_out:
    free(stderr_buffer);
    free(stdout_buffer);
    free(tmp_stdout_buffer);
    return ret;
}

static int check_load_request_valid(const im_load_request *request)
{
    int ret = -1;

    if (request == NULL) {
        ERROR("invalid load request");
        lcrd_set_error_message("invalid load request");
        goto out;
    }

    if (request->file == NULL) {
        ERROR("Load image requires input file path");
        lcrd_set_error_message("Load image requires input file path");
        goto out;
    }

    if (request->tag != NULL) {
        if (util_valid_image_name(request->tag) != true) {
            ERROR("Invalid tag %s", request->tag);
            lcrd_try_set_error_message("Invalid tag:%s", request->tag);
            goto out;
        }
    }

    ret = 0;

out:
    return ret;
}

int oci_load_image(im_load_request *request)
{
    int ret = 0;
    char *ref = NULL;

    if (check_load_request_valid(request) != 0) {
        ret = -1;
        goto pack_response;
    }

    if (!do_load(request, &ref)) {
        ERROR("Failed to load image");
        ret = -1;
        goto pack_response;
    }

    ret = register_new_oci_image_into_memory(ref);
    if (ret != 0) {
        ERROR("Failed to register new image to images store");
        ret = -1;
        goto pack_response;
    }

pack_response:
    free(ref);
    ref = NULL;

    return ret;
}
