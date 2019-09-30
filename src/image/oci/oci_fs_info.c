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
 * Description: provide oci image fs functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "oci_fs_info.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "isula_imtool_interface.h"

static bool do_fs_info(imagetool_fs_info **fs_info)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    parser_error err = NULL;

    command_ret = util_exec_cmd(execute_fs_info, NULL, NULL, &stdout_buffer, &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to get image fs info with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to image fs info with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec inspect fs info command");
            lcrd_set_error_message("Failed to exec inspect fs info command");
        }
        goto free_out;
    }

    if (stdout_buffer == NULL) {
        ERROR("Failed to get image filesystem info becase can not get stdoutput");
        lcrd_set_error_message("Failed to get image filesystem info becase can not get stdoutput");
        goto free_out;
    }

    *fs_info = imagetool_fs_info_parse_data(stdout_buffer, NULL, &err);
    if (*fs_info == NULL) {
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


int get_fs_info(image_fs_info_response **response)
{
    int ret = 0;
    imagetool_fs_info *fs_info = NULL;

    if (response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(image_fs_info_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    EVENT("Event: {Object: sysinfo, Type: inspecting}");

    if (!do_fs_info(&fs_info)) {
        ERROR("Failed to inspect image filesystem info");
        ret = -1;
        goto pack_response;
    }
    EVENT("Event: {Object: sysinfo, Type: inspected}");

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }

    (*response)->fs_info = fs_info;

    return ret;
}

void free_image_fs_info_response(image_fs_info_response *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free_imagetool_fs_info(ptr->fs_info);
    ptr->fs_info = NULL;
    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

