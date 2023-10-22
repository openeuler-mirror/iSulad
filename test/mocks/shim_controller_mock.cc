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
 * Author: jikai
 * Create: 2023-10-20
 * Description: provide shim controller mock
 ******************************************************************************/

#include "shim_controller_mock.h"

namespace sandbox {
static std::shared_ptr<MockShimController> g_shim_controller_mock = nullptr;

ShimController::ShimController(const std::string &sandboxer)
{
}

ShimController::~ShimController()
{
}

void MockShimController_SetMock(std::shared_ptr<MockShimController> mock)
{
    g_shim_controller_mock = mock;
}

bool ShimController::Init(Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Init(error);
    }
    return true;
}

void ShimController::Destroy()
{
    if (g_shim_controller_mock != nullptr) {
        g_shim_controller_mock->Destroy();
    }
}

bool ShimController::Create(const std::string &sandboxId,
                            const ControllerCreateParams &params,
                            Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Create(sandboxId, params, error);
    }
    return true;
}

std::unique_ptr<ControllerSandboxInfo> ShimController::Start(const std::string &sandboxId, Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Start(sandboxId, error);
    }
    return nullptr;
}

std::unique_ptr<ControllerPlatformInfo> ShimController::Platform(const std::string &sandboxId, Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Platform(sandboxId, error);
    }
    return nullptr;
}

std::string ShimController::Prepare(const std::string &sandboxId,
                                    const ControllerPrepareParams &params,
                                    Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Prepare(sandboxId, params, error);
    }
    return "";
}

bool ShimController::Purge(const std::string &sandboxId, const std::string &containerId,
                           const std::string &execId, Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Purge(sandboxId, containerId, execId, error);
    }
    return true;
}

bool ShimController::UpdateResources(const std::string &sandboxId,
                                     const ControllerUpdateResourcesParams &params,
                                     Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->UpdateResources(sandboxId, params, error);
    }
    return true;
}

bool ShimController::Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Stop(sandboxId, timeoutSecs, error);
    }
    return true;
}

bool ShimController::Wait(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Wait(cb, sandboxId, error);
    }
    return true;
}

std::unique_ptr<ControllerSandboxStatus> ShimController::Status(const std::string &sandboxId, bool verbose, Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Status(sandboxId, verbose, error);
    }
    return nullptr;
}

bool ShimController::Shutdown(const std::string &sandboxId, Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->Shutdown(sandboxId, error);
    }
    return true;
}

bool ShimController::UpdateNetworkSettings(const std::string &sandboxId, const std::string &networkSettings, Errors &error)
{
    if (g_shim_controller_mock != nullptr) {
        return g_shim_controller_mock->UpdateNetworkSettings(sandboxId, networkSettings, error);
    }
    return true;
}

}
