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
 * Description: provide oci login image functions
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
#include "oci_auth.h"
#include "oci_login.h"

static bool do_login(im_login_request *request)
{
    bool ret = false;
    bool command_ret = false;
    char *stdout_buffer = NULL;
    char *stderr_buffer = NULL;
    char *stdin_buffer = NULL;
    auth_config auth = {0};

    auth.username = request->username;
    auth.password = request->password;
    stdin_buffer = pack_input_auth_string(&auth);
    if (stdin_buffer == NULL) {
        ERROR("Failed to generate image auth info");
        lcrd_set_error_message("Failed to generate image auth info");
        goto free_out;
    }

    command_ret = util_exec_cmd(execute_login, request, stdin_buffer,
                                &stdout_buffer, &stderr_buffer);
    if (!command_ret) {
        if (stderr_buffer != NULL) {
            ERROR("Failed to login with error: %s", stderr_buffer);
            lcrd_set_error_message("Failed to login with error: %s",
                                   stderr_buffer);
        } else {
            ERROR("Failed to exec login command");
            lcrd_set_error_message("Failed to exec login command");
        }
        goto free_out;
    }

    ret = true;

free_out:
    free_sensitive_string(stdin_buffer);
    free(stderr_buffer);
    free(stdout_buffer);
    return ret;
}

static int check_login_request_valid(const im_login_request *request)
{
    int ret = -1;

    if (request == NULL) {
        ERROR("invalid login request");
        lcrd_set_error_message("invalid login request");
        goto out;
    }

    if (request->server == NULL) {
        ERROR("Login requires server address");
        lcrd_set_error_message("Login requires server address");
        goto out;
    }

    if (request->username == NULL || request->password == NULL) {
        ERROR("Missing username or password");
        lcrd_set_error_message("Missing username or password");
        goto out;
    }

    ret = 0;

out:
    return ret;
}


int oci_login(im_login_request *request)
{
    int ret = 0;

    if (check_login_request_valid(request) != 0) {
        ret = -1;
        goto pack_response;
    }

    if (!do_login(request)) {
        ret = -1;
        goto pack_response;
    }

pack_response:

    return ret;
}
