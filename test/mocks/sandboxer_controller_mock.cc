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
 * Description: provide sandboxer controller mock
 ******************************************************************************/

#include "sandboxer_controller_mock.h"

namespace sandbox {
static std::shared_ptr<MockSandboxerController> g_sandboxer_controller_mock = nullptr;

SandboxerController::SandboxerController(const std::string &sandboxer, const std::string &address)
{
}

SandboxerController::~SandboxerController()
{
}

void MockSandboxerController_SetMock(std::shared_ptr<MockSandboxerController> mock)
{
    g_sandboxer_controller_mock = mock;
}

bool SandboxerController::Init(Errors &error)
{
    if (g_sandboxer_controller_mock != nullptr) {
        return g_sandboxer_controller_mock->Init(error);
    }
    return true;
}

bool SandboxerController::Create(const std::string &sandboxId,
                            const ControllerCreateParams &params,
                            Errors &error)
{
    if (g_sandboxer_controller_mock != nullptr) {
        return g_sandboxer_controller_mock->Create(sandboxId, params, error);
    }
    return true;
}

std::unique_ptr<ControllerSandboxInfo> SandboxerController::Start(const std::string &sandboxId, Errors &error)
{
    if (g_sandboxer_controller_mock != nullptr) {
        return g_sandboxer_controller_mock->Start(sandboxId, error);
    }
    return nullptr;
}

std::unique_ptr<ControllerPlatformInfo> SandboxerController::Platform(const std::string &sandboxId, Errors &error)
{
    if (g_sandboxer_controller_mock != nullptr) {
        return g_sandboxer_controller_mock->Platform(sandboxId, error);
    }
    return nullptr;
}

bool SandboxerController::Update(sandbox_sandbox *apiSandbox,
                            string_array *fields, Errors &error)
{
    return g_sandboxer_controller_mock->Update(apiSandbox, fields, error);
}

bool SandboxerController::Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error)
{
    if (g_sandboxer_controller_mock != nullptr) {
        return g_sandboxer_controller_mock->Stop(sandboxId, timeoutSecs, error);
    }
    return true;
}

bool SandboxerController::Wait(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error)
{
    if (g_sandboxer_controller_mock != nullptr) {
        return g_sandboxer_controller_mock->Wait(cb, sandboxId, error);
    }
    return true;
}

std::unique_ptr<ControllerSandboxStatus> SandboxerController::Status(const std::string &sandboxId, bool verbose,
                                                                Errors &error)
{
    if (g_sandboxer_controller_mock != nullptr) {
        return g_sandboxer_controller_mock->Status(sandboxId, verbose, error);
    }
    return nullptr;
}

bool SandboxerController::Shutdown(const std::string &sandboxId, Errors &error)
{
    if (g_sandboxer_controller_mock != nullptr) {
        return g_sandboxer_controller_mock->Shutdown(sandboxId, error);
    }
    return true;
}

bool SandboxerController::UpdateNetworkSettings(const std::string &sandboxId, const std::string &networkSettings,
                                           Errors &error)
{
    if (g_sandboxer_controller_mock != nullptr) {
        return g_sandboxer_controller_mock->UpdateNetworkSettings(sandboxId, networkSettings, error);
    }
    return true;
}

}
