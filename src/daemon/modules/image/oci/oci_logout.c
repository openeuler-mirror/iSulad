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
* Description: isula logout operator implement
*******************************************************************************/
#include "oci_logout.h"

#include <stddef.h>

#include "err_msg.h"
#include "isula_libutils/log.h"
#include "registry.h"
#include "utils_array.h"
#include "utils_string.h"

static inline int is_valid_arguments(const char *server)
{
    if (server == NULL) {
        isulad_set_error_message("Failed to logout with error: logout requires server address");
        return -1;
    }
    return 0;
}

int oci_do_logout(const char *server)
{
    int ret = -1;
    char *host = NULL;
    char **parts = NULL;

    if (is_valid_arguments(server) != 0) {
        ERROR("Invlaid arguments");
        return -1;
    }

    parts = util_string_split(server, '/');
    if (parts == NULL || util_array_len((const char **)parts) == 0) {
        ret = -1;
        goto out;
    }
    host = parts[0];

    ret = registry_logout((char *)host);
    if (ret != 0) {
        ERROR("registry logout failed");
        isulad_set_error_message("Failed to logout with error: %s", g_isulad_errmsg);
        goto out;
    }

out:
    util_free_array(parts);

    return ret;
}
