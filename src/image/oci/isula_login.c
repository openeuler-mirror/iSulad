/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: isula login operator implement
*******************************************************************************/
#include "isula_login.h"

#include "isula_image_connect.h"
#include "isula_helper.h"
#include "connect.h"
#include "utils.h"
#include "libisulad.h"
#include "isula_libutils/log.h"
#include "registry.h"

static int is_valid_arguments(const char *server, const char *username, const char *password)
{
    if (server == NULL) {
        isulad_set_error_message("Login requires server address");
        return -1;
    }

    if (username == NULL || password == NULL) {
        isulad_set_error_message("Missing username or password");
        return -1;
    }

    return 0;
}

int isula_do_login(const char *server, const char *username, const char *password)
{
    int ret = -1;
    registry_login_options options;

    if (is_valid_arguments(server, username, password) != 0) {
        ERROR("Invalid arguments");
        return -1;
    }

    options.host = (char *) server;
    options.auth.username = (char *) username;
    options.auth.password = (char *) password;
    ret = registry_login(&options);
    if (ret != 0) {
        ERROR("registry login failed");
        goto out;
    }

out:
    return ret;
}
