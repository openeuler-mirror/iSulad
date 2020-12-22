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
 * Create: 2020-12-15
 * Description: provide cri runtime manager service function implementation
 *********************************************************************************/
#include "cri_runtime_manager_service_impl.h"
#include "isula_libutils/log.h"
#include "cri_helpers.h"

namespace CRI {
void RuntimeManagerServiceImpl::UpdateRuntimeConfig(const runtime::v1alpha2::RuntimeConfig &config, Errors & /*error*/)
{
    INFO("iSulad cri received runtime config: %s", config.network_config().pod_cidr().c_str());
    if (m_pluginManager != nullptr && config.has_network_config() && !(config.network_config().pod_cidr().empty())) {
        std::map<std::string, std::string> events;
        events[CRIHelpers::Constants::NET_PLUGIN_EVENT_POD_CIDR_CHANGE_DETAIL_CIDR] =
            config.network_config().pod_cidr();
        m_pluginManager->Event(CRIHelpers::Constants::NET_PLUGIN_EVENT_POD_CIDR_CHANGE, events);
    }
}

auto RuntimeManagerServiceImpl::Status(Errors &error) -> std::unique_ptr<runtime::v1alpha2::RuntimeStatus>
{
    std::unique_ptr<runtime::v1alpha2::RuntimeStatus> status(new (std::nothrow) runtime::v1alpha2::RuntimeStatus);
    if (status == nullptr) {
        error.SetError("Out of memory");
        return nullptr;
    }

    runtime::v1alpha2::RuntimeCondition *runtimeReady = status->add_conditions();
    runtimeReady->set_type(CRIHelpers::Constants::RUNTIME_READY);
    runtimeReady->set_status(true);
    runtime::v1alpha2::RuntimeCondition *networkReady = status->add_conditions();
    networkReady->set_type(CRIHelpers::Constants::NETWORK_READY);
    networkReady->set_status(true);

    container_version_response *response { nullptr };
    if (m_cb == nullptr || m_cb->container.version == nullptr || m_cb->container.version(nullptr, &response) != 0) {
        runtimeReady->set_status(false);
        runtimeReady->set_reason("iSuladDaemonNotReady");
        std::string msg = "iSulad: failed to get iSulad version: ";
        if (response != nullptr && response->errmsg != nullptr) {
            msg += response->errmsg;
        } else {
            msg += "Get version callback failed";
        }
        runtimeReady->set_message(msg);
    }
    free_container_version_response(response);

    // Get status of network
    m_pluginManager->Status(error);
    if (error.NotEmpty()) {
        networkReady->set_status(false);
        networkReady->set_reason("NetworkPluginNotReady");
        networkReady->set_message("iSulad: network plugin is not ready: " + error.GetMessage());
        error.Clear();
    }
    return status;
}

} // namespace CRI