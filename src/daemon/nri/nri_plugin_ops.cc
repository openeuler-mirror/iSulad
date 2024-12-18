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
 * Create: 2024-03-26
 * Description: provide nri plugin api definition
 ******************************************************************************/
#include "nri_plugin_ops.h"

#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "nri_adaption.h"
#include "nri_plugin.h"
#include "isulad_config.h"

static bool start_external_listener()
{
    __isula_auto_free char *sock_path = NULL;

    sock_path = conf_get_socket_path();
    if (sock_path == NULL) {
        ERROR("Failed to get socket path");
        return false;
    }

    if (nri_external_service_start(sock_path, nri_external_plugin_connect) != 0) {
        ERROR("Failed to lauch external service");
        return false;
    }
    return true;
}

bool nri_adaption_init(void)
{
    Errors error;

    if (conf_get_nri_support()) {
        nri_runtime_callbacks callbacks;
        callbacks.register_plugin = nri_registry_containers;
        callbacks.update_containers =  nri_update_containers;
        if (nri_runtime_service_init(callbacks) != 0) {
            ERROR("Failed to init runtime service\n");
            return false;
        }

        if (conf_get_nri_external_support()) {
            if (!start_external_listener()) {
                ERROR("Failed to start external listener\n");
                goto clean_out;
            }
        }
    }

    NRIAdaptation::GetInstance()->Init(error);
    if (error.NotEmpty()) {
        ERROR("Failed to init NRIAdaptation: %s", error.GetCMessage());
        goto clean_out;
    }
    return true;
clean_out:
    nri_runtime_service_destroy();
    return false;
}

bool nri_adaption_shutdown(void)
{
    nri_external_service_shutdown();
    nri_runtime_service_destroy();
    return true;
}

int nri_update_containers(const char *plugin_id, const nri_update_containers_request *request,
                          nri_update_containers_response **response)
{
    if (request == nullptr || response == nullptr || plugin_id == nullptr) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (!NRIAdaptation::GetInstance()->updateContainers(request, response)) {
        ERROR("Failed to update containers by plugin %s", plugin_id);
        return -1;
    }

    return 0;
}

int nri_registry_containers(const char *plugin_id, const nri_register_plugin_request *request)
{
    if (request == nullptr || plugin_id == nullptr) {
        ERROR("Invalid input arguments");
        return -1;
    }

    auto plugin = NRIAdaptation::GetInstance()->GetPluginByIndex(plugin_id);
    if (plugin == nullptr) {
        ERROR("Failed to get plugin by index %s", plugin_id);
        return -1;
    }

    plugin->SetReady();
    return 0;
}

int nri_external_plugin_connect(int fd)
{
    if (fd < 0) {
        ERROR("Invalid input arguments");
        return -1;
    }

    return NRIAdaptation::GetInstance()->NewExternalPlugin(fd) ? 0 : -1;
}