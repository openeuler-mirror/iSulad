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
* Author: wangfengtu
* Create: 2020-05-07
* Description: isula login operator implement
*******************************************************************************/
#include "oci_login.h"

#include <stdbool.h>
#include <string.h>

#include "err_msg.h"
#include "isula_libutils/log.h"
#include "registry.h"
#include "isulad_config.h"
#include "utils_array.h"
#include "utils_string.h"
#include "oci_image.h"

static int is_valid_arguments(const char *server, const char *username, const char *password)
{
    if (server == NULL) {
        isulad_set_error_message("Failed to login with error: login requires server address");
        return -1;
    }

    if (username == NULL || password == NULL) {
        isulad_set_error_message("Failed to login with error: missing username or password");
        return -1;
    }

    return 0;
}

int oci_do_login(const char *server, const char *username, const char *password)
{
    int ret = -1;
    registry_login_options options = { 0 };
    char **insecure_registries = NULL;
    char **registry = NULL;
    char *host = NULL;
    char **parts = NULL;
    struct oci_image_module_data *oci_image_data = NULL;

    if (is_valid_arguments(server, username, password) != 0) {
        ERROR("Invalid arguments");
        return -1;
    }

    parts = util_string_split(server, '/');
    if (parts == NULL || util_array_len((const char **)parts) == 0) {
        ret = -1;
        goto out;
    }
    host = parts[0];

    oci_image_data = get_oci_image_data();
    options.skip_tls_verify = oci_image_data->insecure_skip_verify_enforce;

    insecure_registries = oci_image_data->insecure_registries;
    for (registry = insecure_registries; (registry != NULL) && (*registry != NULL); registry++) {
        if (!strcmp(*registry, host)) {
            options.insecure_registry = true;
        }
    }

    options.host = host;
    options.auth.username = (char *)username;
    options.auth.password = (char *)password;
    ret = registry_login(&options);
    if (ret != 0) {
        ERROR("registry login failed");
        isulad_set_error_message("Failed to login with error: %s", g_isulad_errmsg);
        goto out;
    }

out:
    util_free_array(parts);
    parts = NULL;

    return ret;
}
