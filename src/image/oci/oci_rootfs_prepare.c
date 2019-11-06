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
 * Author: 李峰
 * Create: 2018-11-08
 * Description: provide oci prepare rootfs functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "oci_rootfs_prepare.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "isula_imtool_interface.h"

static bool do_prepare(rootfs_prepare_request *request, imagetool_prepare_response **response)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    parser_error err = NULL;

    command_ret = util_exec_cmd(execute_prepare_rootfs, request, NULL, &stdout_buffer,
                                &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to prepare rootfs with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to prepare rootfs with error: %s",
                                   stderr_buffer);
        } else {
            ERROR("Failed to exec prepare rootfs command");
            lcrd_set_error_message("Failed to exec prepare rootfs command");
        }
        goto free_out;
    }

    if (stdout_buffer == NULL) {
        ERROR("Failed to prepare rootfs becase can not get stdoutput");
        lcrd_set_error_message("Failed to prepare rootfs becase can not get stdoutput");
        goto free_out;
    }

    *response = imagetool_prepare_response_parse_data(stdout_buffer, NULL, &err);
    if (*response == NULL) {
        ERROR("Failed to parse isulad-kit output: %s", stdout_buffer);
        lcrd_set_error_message("Failed to parse isulad-kit output");
        goto free_out;
    }

    ret = true;

free_out:
    free(err);
    free(stderr_buffer);
    free(stdout_buffer);
    return ret;
}

static int check_prepare_request_valid(rootfs_prepare_request *request)
{
    int ret = -1;

    if (request == NULL) {
        ERROR("unvalid prepare request");
        lcrd_set_error_message("unvalid prepare request");
        goto out;
    }

    if (request->image == NULL) {
        ERROR("Prepare rootfs requires an image");
        lcrd_set_error_message("Prepare rootfs requires an image");
        goto out;
    }

    if (request->name == NULL) {
        ERROR("Prepare rootfs requires container name");
        lcrd_set_error_message("Prepare rootfs requires container name");
        goto out;
    }

    ret = 0;

out:
    return ret;
}

int prepare_rootfs_and_get_image_conf(rootfs_prepare_request *request,
                                      rootfs_prepare_and_get_image_conf_response **response)
{
    int ret = 0;
    char *name = NULL;
    char *image = NULL;
    imagetool_prepare_response *tool_response = NULL;

    if (response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(rootfs_prepare_and_get_image_conf_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (check_prepare_request_valid(request) != 0) {
        ret = -1;
        goto pack_response;
    }

    image = request->image;
    name = request->name;

    EVENT("Event: {Object: %s, Type: preparing rootfs with image %s}", name, image);

    if (!do_prepare(request, &tool_response)) {
        ERROR("Failed to prepare rootfs");
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: prepared rootfs with image %s}", name, image);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }

    (*response)->raw_response = tool_response;

    return ret;
}

void free_rootfs_prepare_request(rootfs_prepare_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->image);
    ptr->image = NULL;
    free(ptr->name);
    ptr->name = NULL;
    free(ptr->id);
    ptr->id = NULL;
    util_free_array(ptr->storage_opts);
    ptr->storage_opts = NULL;
    ptr->storage_opts_len = 0;

    free(ptr);
}

void free_rootfs_prepare_and_get_image_conf_response(rootfs_prepare_and_get_image_conf_response *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free_imagetool_prepare_response(ptr->raw_response);
    ptr->raw_response = NULL;

    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

