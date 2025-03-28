/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2024-07-13
 * Description: provide nri helpers functions
 *********************************************************************************/
#ifndef DAEMON_NRI_PLUGIN_NRI_HELPERS_H
#define DAEMON_NRI_PLUGIN_NRI_HELPERS_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <isula_libutils/nri_create_container_request.h>
#include <isula_libutils/nri_create_container_response.h>
#include <isula_libutils/nri_update_container_request.h>
#include <isula_libutils/nri_update_container_response.h>
#include <isula_libutils/nri_container_update.h>
#include <isula_libutils/nri_mount.h>

#include <isula_libutils/container_config.h>
#include <isula_libutils/host_config.h>

#include "errors.h"
#include "utils.h"

namespace NRIHelpers {
std::string MarkForRemoval(const std::string &key);

auto GetPluginConfig(std::string &idx, std::string &name, std::string &config) -> bool;

void GenerateRandomExternalName(std::string &ret);

bool CheckPluginIndex(const std::string &idx);

void FreeNriContainerUpdateVector(std::vector<nri_container_update *> &vec);
void FreeNriContainerVector(std::vector<nri_container *> &vec);
void FreeNriPodVector(std::vector<nri_pod_sandbox *> &vec);

template <typename T>
void freeArray(T ** &arr, int size)
{
    if (arr == NULL) {
        return;
    }

    for (int i = 0; i < size; i++) {
        if (arr[i] == NULL) {
            return;
        }
        free(arr[i]);
    }

    free(arr);
    arr = NULL;
}

template <typename T>
T* copy_pointer(T* value)
{
    if (value == nullptr) {
        return nullptr;
    }
    T* result = (T *)util_common_calloc_s(sizeof(T));
    if (result == nullptr) {
        return nullptr;
    }
    *result = *value;
    return result;
}
}; // namespace NRIHelpers

#endif // DAEMON_NRI_PLUGIN_NRI_HELPERS_H
