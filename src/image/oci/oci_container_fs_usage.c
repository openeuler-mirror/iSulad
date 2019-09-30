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
#include "oci_container_fs_usage.h"
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "oci_fs_info.h"
#include "log.h"
#include "utils.h"
#include "liblcrd.h"
#include "isula_imtool_interface.h"
#include "oci_rootfs_prepare.h"

bool do_oci_container_fs_info(char *id, imagetool_fs_info **fs_info)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    parser_error err = NULL;

    if (id == NULL || fs_info == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    command_ret = util_exec_cmd(execute_container_fs_info, id, NULL, &stdout_buffer, &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to get container fs info with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to container fs info with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec inspect fs info command");
            lcrd_set_error_message("Failed to exec inspect fs info command");
        }
        goto free_out;
    }

    if (stdout_buffer == NULL) {
        ERROR("Failed to get container filesystem info becase can not get stdoutput");
        lcrd_set_error_message("Failed to get container filesystem info becase can not get stdoutput");
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
    free(stdout_buffer);
    free(stderr_buffer);
    return ret;
}
