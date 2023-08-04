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
 * Author: xuxuepeng
 * Create: 2023-07-06
 * Description: provide sandboxer controller implementation
 *********************************************************************************/

#include "sandboxer_controller.h"

namespace sandbox {

SandboxerController::SandboxerController(const std::string &sandboxer, const std::string &address)
    : m_sandboxer(sandboxer), m_address(address)
{
    m_client = std::make_shared<SandboxerClient>(m_sandboxer, m_address);
}

SandboxerController::~SandboxerController() {}

bool SandboxerController::Init(Errors &error)
{
    m_client->Init(error);
    return true;
}

void SandboxerController::Destroy()
{
    m_client->Destroy();
}

bool SandboxerController::Create(const std::string &sandboxId,
                                 const ControllerCreateParams &params,
                                 Errors &error)
{
    return m_client->Create(sandboxId, params, error);
}

std::unique_ptr<ControllerSandboxInfo> SandboxerController::Start(const std::string &sandboxId, Errors &error)
{
    std::unique_ptr<ControllerSandboxInfo> sandboxInfo(new ControllerSandboxInfo());
    if (!m_client->Start(sandboxId, *sandboxInfo, error)) {
        return nullptr;
    }
    return sandboxInfo;
}

std::unique_ptr<ControllerPlatformInfo> SandboxerController::Platform(const std::string &sandboxId, Errors &error)
{
    std::unique_ptr<ControllerPlatformInfo> platformInfo(new ControllerPlatformInfo());
    if (!m_client->Platform(sandboxId, *platformInfo, error)) {
        return nullptr;
    }
    return platformInfo;
}

std::string SandboxerController::Prepare(const std::string &sandboxId,
                                         const ControllerPrepareParams &params,
                                         Errors &error)
{
    std::string bundle;
    if (!m_client->Prepare(sandboxId, params, bundle, error)) {
        return "";
    }
    return bundle;
}

bool SandboxerController::Purge(const std::string &sandboxId, const std::string &containerId,
                                const std::string &execId, Errors &error)
{
    return m_client->Purge(sandboxId, containerId, execId, error);
}

bool SandboxerController::UpdateResources(const std::string &sandboxId,
                                          const ControllerUpdateResourcesParams &params,
                                          Errors &error)
{
    return m_client->UpdateResources(sandboxId, params, error);
}

bool SandboxerController::Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error)
{
    return m_client->Stop(sandboxId, timeoutSecs, error);
}

bool SandboxerController::Wait(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error)
{
    return true;
}

std::unique_ptr<ControllerSandboxStatus> SandboxerController::Status(const std::string &sandboxId, bool verbose,
                                                                     Errors &error)
{
    std::unique_ptr<ControllerSandboxStatus> sandboxStatus(new ControllerSandboxStatus());
    if (!m_client->Status(sandboxId, verbose, *sandboxStatus, error)) {
        return nullptr;
    }
    return sandboxStatus;
}

bool SandboxerController::Shutdown(const std::string &sandboxId, Errors &error)
{
    return m_client->Shutdown(sandboxId, error);
}

bool SandboxerController::UpdateNetworkSettings(const std::string &sandboxId, const std::string &networkSettings,
                                                Errors &error)
{
    return true;
}

} // namespace sandbox
