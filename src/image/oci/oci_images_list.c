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
 * Description: provide oci images list functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include "oci_images_list.h"
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "log.h"
#include "utils.h"
#include "liblcrd.h"
#include "image.h"
#include "isula_imtool_interface.h"

static void set_char_to_terminator(char *p)
{
    *p = '\0';
}

static void util_log_output(char *output)
{
    size_t len = 0;
    char *tmp_start = NULL;
    char *tmp_end = NULL;

    if (output == NULL) {
        return;
    }

    len = strlen(output);

    for (tmp_start = output; tmp_start < (output + len) && tmp_start != NULL;) {
        tmp_end = strchr(tmp_start, '\n');
        if (tmp_end == NULL) {
            ERROR("%s", tmp_start);
            break;
        }
        set_char_to_terminator(tmp_end);
        ERROR("%s", tmp_start);
        *tmp_end = '\n';
        tmp_start = tmp_end + 1;
    }

    return;
}

int do_list_oci_images(im_list_request *request, imagetool_images_list **images)
{
    int ret = -1;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    parser_error err = NULL;

    if (request == NULL || images == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    command_ret = util_exec_cmd(execute_list_images, request, NULL, &stdout_buffer,
                                &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to list images with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to list images with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec list images command");
            lcrd_set_error_message("Failed to exec list images command");
        }
        goto free_out;
    }

    if (request->check && stderr_buffer != NULL) {
        util_log_output(stderr_buffer);
    }

    if (stdout_buffer == NULL) {
        ERROR("Failed to list images becase can not get stdoutput");
        lcrd_set_error_message("Failed to list images becase can not get stdoutput");
        goto free_out;
    }

    *images = imagetool_images_list_parse_data(stdout_buffer, NULL, &err);
    if (*images == NULL) {
        ERROR("Failed to parse output json:%s", err);
        lcrd_set_error_message("Failed to parse output json:%s", err);
        goto free_out;
    }

    ret = 0;

free_out:
    free(err);
    free(stderr_buffer);
    free(stdout_buffer);
    return ret;
}
