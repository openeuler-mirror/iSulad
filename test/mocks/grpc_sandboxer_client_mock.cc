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
 * Create: 2023-07-15
 * Description: provide grpc sandboxer client mock
 ******************************************************************************/

#include "grpc_sandboxer_client_mock.h"

static std::shared_ptr<SandboxerClientMock> g_sandboxer_client_mock = NULL;

SandboxerClient::SandboxerClient(const std::string &sandboxer, const std::string &address)
{
    m_sandboxer = sandboxer;
    m_address = address;
}

auto SandboxerClient::Create(const std::string &sandboxId, const ControllerCreateParams &params, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->Create(sandboxId, params, error);
}

auto SandboxerClient::Start(const std::string &sandboxId, ControllerSandboxInfo &sandboxInfo, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->Start(sandboxId, sandboxInfo, error);
}

auto SandboxerClient::Platform(const std::string &sandboxId, ControllerPlatformInfo &platformInfo, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->Platform(sandboxId, platformInfo, error);
}

auto SandboxerClient::Prepare(const std::string &sandboxId, const ControllerPrepareParams &params, std::string &bundle, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->Prepare(sandboxId, params, bundle, error);
}

auto SandboxerClient::Purge(const std::string &sandboxId, const std::string &containerId,
                            const std::string &execId, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->Purge(sandboxId, containerId, execId, error);
}

auto SandboxerClient::UpdateResources(const std::string &sandboxId, const ControllerUpdateResourcesParams &params, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->UpdateResources(sandboxId, params, error);
}

auto SandboxerClient::Stop(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->Stop(sandboxId, timeoutSecs, error);
}

auto SandboxerClient::Wait(const std::string &sandboxId, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->Wait(sandboxId, error);
}

auto SandboxerClient::Status(const std::string &sandboxId, bool verbose, ControllerSandboxStatus &sandboxStatus, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->Status(sandboxId, verbose, sandboxStatus, error);
}

auto SandboxerClient::Shutdown(const std::string &sandboxId, Errors &error) -> bool
{
    if (g_sandboxer_client_mock == NULL) {
        return true;
    }
    return g_sandboxer_client_mock->Shutdown(sandboxId, error);
}

void MockSandboxerClient_SetMock(std::shared_ptr<SandboxerClientMock> mock)
{
    g_sandboxer_client_mock = mock;
}