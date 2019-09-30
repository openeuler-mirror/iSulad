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
 * Description: provide oci remove rootfs functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "oci_rootfs_remove.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "isula_imtool_interface.h"

#define CONTAINER_NOT_KNOWN_ERR "container not known"

static bool do_remove(rootfs_remove_request *request)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;

    command_ret = util_exec_cmd(execute_remove_rootfs, request, NULL, &stdout_buffer,
                                &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            if (strstr(stderr_buffer, CONTAINER_NOT_KNOWN_ERR) != NULL) {
                DEBUG("Container %s may already removed", request->name_id);
                ret = true;
                goto free_out;
            }
            ERROR("Failed to remove rootfs with error: %s", stderr_buffer);
            lcrd_try_set_error_message("Failed to remove rootfs with error: %s", stderr_buffer);
        } else {
            ERROR("Failed to exec remove rootfs command");
            lcrd_try_set_error_message("Failed to exec remove rootfs command");
        }
        goto free_out;
    }

    ret = true;

free_out:
    free(stderr_buffer);
    free(stdout_buffer);
    return ret;
}

static int check_remove_request_valid(rootfs_remove_request *request)
{
    int ret = -1;

    if (request == NULL) {
        ERROR("unvalid remove request");
        lcrd_set_error_message("unvalid remove request");
        goto out;
    }

    if (request->name_id == NULL) {
        ERROR("remove rootfs requires container name or id");
        lcrd_set_error_message("remove rootfs requires container name or id");
        goto out;
    }

    ret = 0;

out:
    return ret;
}


int remove_rootfs(rootfs_remove_request *request,
                  rootfs_remove_response **response)
{
    int ret = 0;
    char *name_id = NULL;

    if (response == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(rootfs_remove_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (check_remove_request_valid(request) != 0) {
        ret = -1;
        goto pack_response;
    }

    name_id = request->name_id;

    EVENT("Event: {Object: %s, Type: removeing rootfs}", name_id);

    if (!do_remove(request)) {
        ERROR("Failed to remove rootfs");
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: removed rootfs}", name_id);

pack_response:
    if (g_lcrd_errmsg != NULL) {
        (*response)->errmsg = util_strdup_s(g_lcrd_errmsg);
    }

    return ret;
}

void free_rootfs_remove_request(rootfs_remove_request *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->name_id);
    ptr->name_id = NULL;

    free(ptr);
}

void free_rootfs_remove_response(rootfs_remove_response *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free(ptr->errmsg);
    ptr->errmsg = NULL;

    free(ptr);
}

