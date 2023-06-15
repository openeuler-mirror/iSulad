/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2023-06-09
 * Description: provide cri unify services
 ******************************************************************************/
#include "cri_service.h"

#include <isula_libutils/log.h>

#include "stream_server.h"
#include "errors.h"
#include "cri_helpers.h"

using namespace CRIUnify;

void CRIService::doNetworkInit(Network::NetworkPluginConf &mConf, Errors &err)
{
    std::vector<std::shared_ptr<Network::NetworkPlugin>> plugins;
    Network::ProbeNetworkPlugins(mConf.GetPluginConfDir(), mConf.GetPluginBinDir(), &plugins);

    std::shared_ptr<Network::NetworkPlugin> chosen { nullptr };
    Network::InitNetworkPlugin(&plugins, mConf.GetPluginName(), mConf.GetHairpinMode(), mConf.GetNonMasqueradeCIDR(),
                               mConf.GetMTU(), &chosen, err);
    if (err.NotEmpty()) {
        ERROR("Init network plugin failed: %s", err.GetCMessage());
        return;
    }

    m_pluginManager = std::make_shared<Network::PluginManager>(chosen);
}

int CRIService::Init(const isulad_daemon_configs *config)
{
    if (config == nullptr) {
        ERROR("isulad config socket address is empty");
        return -1;
    }

    Errors err;
     /* note: get config from args, now use defaults */
    Network::NetworkPluginConf mConf;

    if (config != nullptr) {
        if (config->network_plugin != nullptr) {
            mConf.SetPluginName(config->network_plugin);
        }
        if (config->cni_bin_dir != nullptr) {
            mConf.SetPluginBinDir(config->cni_bin_dir);
        }
        if (config->cni_conf_dir != nullptr) {
            mConf.SetPluginConfDir(config->cni_conf_dir);
        }
        if (config->pod_sandbox_image != nullptr) {
            m_podSandboxImage = config->pod_sandbox_image;
        }
    }

    if (m_podSandboxImage.empty()) {
        m_podSandboxImage = CRIHelpers::GetDefaultSandboxImage(err);
        if (err.NotEmpty()) {
            return -1;
        }
    }

    // init Network plugin for CRI service
    doNetworkInit(mConf, err);
    if (err.NotEmpty()) {
        return -1;
    }

    m_runtimeRuntimeService.Init(m_podSandboxImage, m_pluginManager, err);
    if (err.NotEmpty()) {
        ERROR("Init CRI v1alpha runtime service failed: %s", err.GetCMessage());
        return -1;
    }

#ifdef ENABLE_CRI_API_V1
    m_runtimeV1RuntimeService.Init(m_podSandboxImage, m_pluginManager, err);
    if (err.NotEmpty()) {
        ERROR("Init CRI v1 runtime service failed: %s", err.GetCMessage());
        return -1;
    }
#endif

    websocket_server_init(err);
    if (err.NotEmpty()) {
        ERROR("Init stream server failed: %s", err.GetMessage().c_str());
        return -1;
    }

    return 0;
}

void CRIService::Register(grpc::ServerBuilder &sb)
{
    // Register CRI v1alpha services, runtime and image
    sb.RegisterService(&m_runtimeRuntimeService);
    sb.RegisterService(&m_runtimeImageService);

#ifdef ENABLE_CRI_API_V1
    // Register CRI v1 services, runtime and image
    sb.RegisterService(&m_runtimeV1RuntimeService);
    sb.RegisterService(&m_runtimeV1ImageService);
#endif
}

void CRIService::Wait(void)
{
    m_runtimeRuntimeService.Wait();
#ifdef ENABLE_CRI_API_V1
    m_runtimeV1RuntimeService.Wait();
#endif
    websocket_server_wait();
}

void CRIService::Shutdown(void)
{
    m_runtimeRuntimeService.Shutdown();
#ifdef ENABLE_CRI_API_V1
    m_runtimeV1RuntimeService.Shutdown();
#endif
    websocket_server_shutdown();
}
