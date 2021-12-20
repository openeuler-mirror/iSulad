/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: chengzeruizhi
 * Create: 2021-10-19
 * Description: set up CRI network namespace
 *********************************************************************************/
#define _GNU_SOURCE

#include "network_namespace_api.h"

#include <sys/mount.h>

#include "utils_network.h"

int remove_network_namespace(const char *netns_path)
{
    int get_err = 0;

    if (netns_path == NULL) {
        ERROR("Invalid netns_path");
        return -1;
    }

    if (!util_file_exists(netns_path)) {
        WARN("Namespace file does not exist");
        return 0;
    }

    if (umount2(netns_path, MNT_DETACH) != 0 && errno != EINVAL) {
        ERROR("Failed to umount directory %s:%s", netns_path, strerror(errno));
        return -1;
    }

    if (!util_force_remove_file(netns_path, &get_err)) {
        ERROR("Failed to remove file %s, error: %s", netns_path, strerror(get_err));
        return -1;
    }

    return 0;
}

char *get_sandbox_key(const container_inspect *inspect_data)
{
    char *sandbox_key = NULL;

    if (inspect_data == NULL) {
        ERROR("Invalid container");
        return NULL;
    }
    if (inspect_data->network_settings == NULL) {
        ERROR("Inspect data does not have network settings");
        return NULL;
    }
    sandbox_key = util_strdup_s(inspect_data->network_settings->sandbox_key);

    return sandbox_key;
}