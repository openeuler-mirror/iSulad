/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#include "nri_helpers.h"

#include <isula_libutils/log.h>

#include "isulad_config.h"

namespace NRIHelpers {
std::string MarkForRemoval(const std::string &key)
{
    return "-" + key;
}

auto GetPluginConfig(std::string &idx, std::string &name, std::string &config) -> bool
{
    __isula_auto_free char *plugin_path = NULL;

    plugin_path = conf_get_nri_plugin_config_path();
    if (plugin_path == NULL) {
        return false;
    }
    std::string compleName = idx + "-" + name;
    std::vector<std::string> dropIns = {
        std::string(plugin_path) + "/" + compleName + ".conf",
        std::string(plugin_path) + "/" + name + ".conf"
    };

    for (const std::string &path : dropIns) {
        char buf[MAX_BUFFER_SIZE + 1] = { 0 };
        __isula_auto_close int fd = util_open(path.c_str(), O_RDONLY, 0);
        if (fd < 0) {
            ERROR("Failed to open '%s'", path.c_str());
            return false;
        }
        int len = util_read_nointr(fd, buf, sizeof(buf) - 1);
        if (len < 0) {
            SYSERROR("Failed to read nri plugin config : %s", path.c_str());
            return false;
        }
        config = std::string(buf);
        return true;
    }
    return true;
}

void GenerateRandomExternalName(std::string &ret)
{
    __isula_auto_free char *external_name = NULL;

    external_name = (char *)util_smart_calloc_s(sizeof(char), (CONTAINER_ID_MAX_LEN + 1));
    if (external_name == NULL) {
        ERROR("Out of memory");
        return;
    }

    if (util_generate_random_str(external_name, (size_t)CONTAINER_ID_MAX_LEN)) {
        ERROR("Generate exec suffix failed");
        return;
    }

    ret = std::string(external_name);
}

bool CheckPluginIndex(const std::string &idx)
{
    if (idx.length() != 2) {
        ERROR("Invalid plugin index \"%s\", must be 2 digits", idx.c_str());
        return false;
    }

    if (!std::isdigit(idx[0]) || !std::isdigit(idx[1])) {
        ERROR("Invalid plugin index \"%s\", (not [0-9][0-9])", idx.c_str());
        return false;
    }

    return true;
}

void FreeNriContainerUpdateVector(std::vector<nri_container_update *> &vec)
{
    for (auto ptr : vec) {
        free_nri_container_update(ptr);
    }
}

void FreeNriContainerVector(std::vector<nri_container *> &vec)
{
    for (auto ptr : vec) {
        free_nri_container(ptr);
    }
}

void FreeNriPodVector(std::vector<nri_pod_sandbox *> &vec)
{
    for (auto ptr : vec) {
        free_nri_pod_sandbox(ptr);
    }
}
}// namespace NRIHelpers