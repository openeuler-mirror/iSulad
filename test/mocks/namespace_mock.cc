/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-02-14
 * Description: provide namespace mock
 ******************************************************************************/

#include "namespace_mock.h"

namespace {
MockNamespace *g_namespace_mock = nullptr;
}

void MockNamespace_SetMock(MockNamespace* mock)
{
    g_namespace_mock = mock;
}

char *namespace_get_connected_container(const char *mode)
{
    if (g_namespace_mock != nullptr) {
        return g_namespace_mock->ConnectedContainer(mode);
    }
    return nullptr;
}

int get_share_namespace_path(const char *type, const char *src_path, char **dest_path)
{
    if (g_namespace_mock != nullptr) {
        return g_namespace_mock->GetShareNamespacePath(type, src_path, dest_path);
    }
    return 0;
}

int get_network_namespace_path(const host_config *host_spec, const container_network_settings *network_settings,
                               const char *type, char **dest_path)
{
    if (g_namespace_mock != nullptr) {
        return g_namespace_mock->GetNetworkNamespacePath(host_spec, network_settings, type, dest_path);
    }
    return 0;
}

char *get_container_process_label(const char *path)
{
    if (g_namespace_mock != nullptr) {
        return g_namespace_mock->GetContainerProcessLabel(path);
    }
    return nullptr;
}

int get_network_namespace_path(const host_config *host_spec,
                               const container_config_v2_common_config_network_settings *network_settings,
                               const char *type, char **dest_path)
{
    if (g_namespace_mock != nullptr) {
        return g_namespace_mock->GetNetworkNamespacePath(host_spec, network_settings, type, dest_path);
    }
    return 0;
}