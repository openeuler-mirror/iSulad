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
#include "utils.h"
#include "libisulad.h"
#include "log.h"
#include "registry.h"

static inline int is_valid_arguments(const char *server)
{
    if (server == NULL) {
        isulad_set_error_message("Logout requires server address");
        return -1;
    }
    return 0;
}

int oci_do_logout(const char *server)
{
    int ret = -1;

    if (is_valid_arguments(server) != 0) {
        ERROR("Invlaid arguments");
        return -1;
    }

    ret = registry_logout((char *)server);
    if (ret != 0) {
        ERROR("registry logout failed");
        goto out;
    }

out:

    return ret;
}
