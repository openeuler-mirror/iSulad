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
 * Create: 2019-06-18
 * Description: provide oci logout image functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "securec.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "isula_imtool_interface.h"
#include "image.h"
#include "oci_logout.h"

static bool do_logout(im_logout_request *request)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;

    command_ret = util_exec_cmd(execute_logout, request, NULL, &stdout_buffer,
                                &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to logout with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to logout with error: %s",
                                   stderr_buffer);
        } else {
            ERROR("Failed to exec logout command");
            lcrd_set_error_message("Failed to exec logout command");
        }
        goto free_out;
    }

    ret = true;

free_out:
    free(stderr_buffer);
    free(stdout_buffer);
    return ret;
}

static int check_logout_request_valid(const im_logout_request *request)
{
    int ret = -1;

    if (request == NULL) {
        ERROR("invalid logout request");
        lcrd_set_error_message("invalid logout request");
        goto out;
    }

    if (request->server == NULL) {
        ERROR("Logout requires server address");
        lcrd_set_error_message("Logout requires server address");
        goto out;
    }

    ret = 0;

out:
    return ret;
}


int oci_logout(im_logout_request *request)
{
    int ret = 0;

    if (check_logout_request_valid(request) != 0) {
        ret = -1;
        goto pack_response;
    }

    if (!do_logout(request)) {
        ret = -1;
        goto pack_response;
    }

pack_response:

    return ret;
}
