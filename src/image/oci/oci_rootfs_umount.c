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
 * Description: provide oci umount rootfs functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "oci_rootfs_umount.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "isula_imtool_interface.h"

static bool do_umount(rootfs_umount_request *request)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;

    command_ret = util_exec_cmd(execute_umount_rootfs, request, NULL, &stdout_buffer, &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to umount rootfs with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to umount rootfs with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec umount rootfs command");
            lcrd_set_error_message("Failed to exec umount rootfs command");
        }
        goto free_out;
    }

    ret = true;

free_out:
    free(stderr_buffer);
    free(stdout_buffer);
    return ret;
}

static int check_umount_request_valid(rootfs_umount_request *request)
{
    int ret = -1;

    if (request == NULL) {
        ERROR("unvalid umount request");
        lcrd_set_error_message("unvalid umount request");
        goto out;
    }

    if (request->name_id == NULL) {
        ERROR("Umount rootfs requires container name or id");
        lcrd_set_error_message("Umount rootfs requires container name or id");
        goto out;
    }

    ret = 0;

out:
    return ret;
}


int umount_rootfs(rootfs_umount_request *request,
                  rootfs_umount_response **response)
{
    int ret = 0;
    char *name_id = NULL;

    if (response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(rootfs_umount_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (check_umount_request_valid(request) != 0) {
        ret = -1;
        goto pack_response;
    }

    name_id = request->name_id;

    EVENT("Event: {Object: %s, Type: umounting rootfs}", name_id);

    if (!do_umount(request)) {
        ERROR("Failed to umount rootfs");
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: umounted rootfs}", name_id);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }

    return ret;
}

void free_rootfs_umount_request(rootfs_umount_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->name_id);
    ptr->name_id = NULL;

    free(ptr);
}

void free_rootfs_umount_response(rootfs_umount_response *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

