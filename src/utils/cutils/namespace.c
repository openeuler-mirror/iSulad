/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide namespace functions
 ******************************************************************************/
#include "namespace.h"

#include <string.h>
#include <isula_libutils/auto_cleanup.h>

#include "utils.h"

char *namespace_get_connected_container(const char *mode)
{
    if (namespace_is_container(mode)) {
        const char *p = mode + strlen(SHARE_NAMESPACE_PREFIX);
        return util_strdup_s(p);
    }

    return NULL;
}

char *namespace_get_host_namespace_path(const char *type)
{
    if (type == NULL) {
        return NULL;
    }
    if (strcmp(type, TYPE_NAMESPACE_PID) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_PID_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_NETWORK) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_NET_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_IPC) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_IPC_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_UTS) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_UTS_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_MOUNT) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_MNT_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_USER) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_USER_HOST_PATH);
    } else if (strcmp(type, TYPE_NAMESPACE_CGROUP) == 0) {
        return util_strdup_s(SHARE_NAMESPACE_CGROUP_HOST_PATH);
    }
    return NULL;
}

#ifdef ENABLE_CRI_API_V1
bool namespace_is_sandbox(const char *mode, const container_sandbox_info *sandbox_info)
{
    __isula_auto_free char *connected_id = NULL;

    if (sandbox_info == NULL) {
        return false;
    }

    if (sandbox_info->id == NULL) {
        return false;
    }

    connected_id = namespace_get_connected_container(mode);
    if (connected_id == NULL) {
        return false;
    }

    return strcmp(sandbox_info->id, connected_id) == 0;
}
#endif
