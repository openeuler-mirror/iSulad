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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide cri runtime service function
 *********************************************************************************/
#include "cri_runtime_service.h"

#include <iostream>
#include <memory>
#include <vector>
#include <map>
#include <string>
#include <grpc++/grpc++.h>
#include <unistd.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "config.h"
#include "isula_libutils/host_config.h"
#include "cri_helpers.h"
#include "network_plugin.h"
#include "isula_libutils/container_inspect.h"

namespace CRIRuntimeService {
std::string Constants::namespaceModeHost { "host" };
std::string Constants::nameDelimiter { "_" };
char Constants::nameDelimiterChar { '_' };
std::string Constants::kubePrefix { "k8s" };
std::string Constants::sandboxContainerName { "POD" };
std::string Constants::kubeAPIVersion { "0.1.0" };
std::string Constants::iSulaRuntimeName { "iSulad" };
std::string Constants::RESOLV_CONF_PATH { "/etc/resolv.conf" };
} // namespace CRIRuntimeService
CRIRuntimeServiceImpl::CRIRuntimeServiceImpl()
{
    m_cb = get_service_executor();
    if (m_cb == nullptr) {
        ERROR("Get callback failed");
    }
}

void CRIRuntimeServiceImpl::VersionResponseToGRPC(container_version_response *response,
                                                  runtime::v1alpha2::VersionResponse *gResponse, Errors &error)
{
    gResponse->set_version(CRIRuntimeService::Constants::kubeAPIVersion);
    gResponse->set_runtime_name(CRIRuntimeService::Constants::iSulaRuntimeName);
    gResponse->set_runtime_version(response->version ? response->version : "");
    gResponse->set_runtime_api_version(VERSION);
}

void CRIRuntimeServiceImpl::Init(Network::NetworkPluginConf mConf, const std::string &podSandboxImage, Errors &err)
{
    if (!podSandboxImage.empty()) {
        m_podSandboxImage = podSandboxImage;
    } else {
        m_podSandboxImage = CRIHelpers::GetDefaultSandboxImage(err);
        if (err.NotEmpty()) {
            return;
        }
    }

    std::vector<std::shared_ptr<Network::NetworkPlugin>> plugins;
    Network::ProbeNetworkPlugins(mConf.GetPluginConfDir(), mConf.GetPluginBinDir(), &plugins);

    std::shared_ptr<Network::NetworkPlugin> chosen { nullptr };
    Network::InitNetworkPlugin(&plugins, mConf.GetPluginName(), this, mConf.GetHairpinMode(),
                               mConf.GetNonMasqueradeCIDR(), mConf.GetMTU(), &chosen, err);
    if (err.NotEmpty()) {
        ERROR("Init network plugin failed: %s", err.GetCMessage());
        return;
    }

    m_pluginManager = std::make_shared<Network::PluginManager>(chosen);
}

void CRIRuntimeServiceImpl::Version(const std::string &apiVersion, runtime::v1alpha2::VersionResponse *versionResponse,
                                    Errors &error)
{
    (void)apiVersion;

    if (m_cb == nullptr || m_cb->container.version == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }

    container_version_response *response { nullptr };
    if (m_cb->container.version(nullptr, &response) != 0) {
        if (response != nullptr && response->errmsg) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call version callback");
        }
        goto cleanup;
    }
    VersionResponseToGRPC(response, versionResponse, error);

cleanup:
    free_container_version_response(response);
}

void CRIRuntimeServiceImpl::UpdateRuntimeConfig(const runtime::v1alpha2::RuntimeConfig &config, Errors &error)
{
    INFO("iSulad cri received runtime config: %s", config.network_config().pod_cidr().c_str());
    if (m_pluginManager != nullptr && config.has_network_config() && !(config.network_config().pod_cidr().empty())) {
        std::map<std::string, std::string> events;
        events[CRIHelpers::Constants::NET_PLUGIN_EVENT_POD_CIDR_CHANGE_DETAIL_CIDR] =
            config.network_config().pod_cidr();
        m_pluginManager->Event(CRIHelpers::Constants::NET_PLUGIN_EVENT_POD_CIDR_CHANGE, events);
    }
    return;
}

std::unique_ptr<runtime::v1alpha2::RuntimeStatus> CRIRuntimeServiceImpl::Status(Errors &error)
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

std::string CRIRuntimeServiceImpl::GetNetNS(const std::string &podSandboxID, Errors &err)
{
    int ret;
    char fullpath[PATH_MAX] { 0 };
    std::string result { "" };
    const std::string NetNSFmt { "/proc/%d/ns/net" };

    container_inspect *inspect_data = InspectContainer(podSandboxID, err);
    if (inspect_data == nullptr) {
        goto cleanup;
    }
    if (inspect_data->state->pid == 0) {
        err.Errorf("cannot find network namespace for the terminated container %s", podSandboxID.c_str());
        goto cleanup;
    }
    ret = snprintf(fullpath, sizeof(fullpath), NetNSFmt.c_str(), inspect_data->state->pid);
    if ((size_t)ret >= sizeof(fullpath) || ret < 0) {
        err.SetError("Sprint nspath failed");
        goto cleanup;
    }
    result = fullpath;

cleanup:
    free_container_inspect(inspect_data);
    return result;
}
