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
 * Author: zhongtao
 * Create: 2023-07-18
 * Description: provide sandbox mock
 ******************************************************************************/

#include <gmock/gmock.h>
#include "sandbox_mock.h"

namespace sandbox {
MockSandbox *g_sandbox_mock = nullptr;

static const std::string defaultStr;
std::vector<std::string> defaultVec;
StatsInfo statsInfo;
static const std::string defaultName = "test";
runtime::v1::PodSandboxConfig defaultConfig;

Sandbox::Sandbox(const std::string id, const std::string &rootdir, const std::string &statedir, const std::string name,
                 const RuntimeInfo info, std::string netMode, std::string netNsPath, const runtime::v1::PodSandboxConfig sandboxConfig,
                 std::string image)
{
    m_name = defaultName;
}

void MockSandbox_SetMock(MockSandbox *mock)
{
    g_sandbox_mock = mock;
}

bool Sandbox::IsReady()
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->IsReady();
    }
    return true;
}

const std::string &Sandbox::GetId() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetId();
    }
    return defaultStr;
}

const std::string &Sandbox::GetName() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetName();
    }
    return defaultStr;
}

const std::string &Sandbox::GetSandboxer() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetSandboxer();
    }
    return defaultStr;
}

const std::string &Sandbox::GetRuntimeHandle() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetRuntimeHandle();
    }
    return defaultStr;
}

const runtime::v1::PodSandboxConfig &Sandbox::GetSandboxConfig() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetSandboxConfig();
    }
    return defaultConfig;
}

std::shared_ptr<runtime::v1::PodSandboxConfig> Sandbox::GetMutableSandboxConfig()
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetMutableSandboxConfig();
    }
    return nullptr;
}

const std::string &Sandbox::GetRootDir() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetRootDir();
    }
    return defaultStr;
}

const std::string &Sandbox::GetStateDir() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetStateDir();
    }
    return defaultStr;
}

std::string Sandbox::GetResolvPath() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetResolvPath();
    }
    return nullptr;
}

std::string Sandbox::GetShmPath() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetShmPath();
    }
    return nullptr;
}

StatsInfo Sandbox::GetStatsInfo()
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetStatsInfo();
    }
    return statsInfo;
}

bool Sandbox::GetNetworkReady() const
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->GetNetworkReady();
    }
    return true;
}

void Sandbox::SetController(std::shared_ptr<Controller> controller) {}
void Sandbox::AddAnnotations(const std::string &key, const std::string &value) {}
void Sandbox::RemoveAnnotations(const std::string &key) {}
void Sandbox::AddLabels(const std::string &key, const std::string &value) {}
void Sandbox::RemoveLabels(const std::string &key) {}
void Sandbox::UpdateNetworkSettings(const std::string &settingsJson, Errors &error) {}
void Sandbox::PrepareSandboxDirs(Errors &error) {}
void Sandbox::CleanupSandboxDirs() {}

StatsInfo Sandbox::UpdateStatsInfo(const StatsInfo &info)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->UpdateStatsInfo(info);
    }
    return statsInfo;
}

void Sandbox::SetNetworkReady(bool ready) {}

bool Sandbox::Save(Errors &error)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->Save(error);
    }
    return true;
}

bool Sandbox::Load(Errors &error)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->Load(error);
    }
    return true;
}

void Sandbox::OnSandboxReady() {}

void Sandbox::OnSandboxPending() {}

void Sandbox::OnSandboxExit(const ControllerExitInfo &exitInfo) {}

bool Sandbox::UpdateStatus(Errors &error)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->UpdateStatus(error);
    }
    return true;
}

bool Sandbox::Create(Errors &error)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->Create(error);
    }
    return true;
}

bool Sandbox::Start(Errors &error)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->Start(error);
    }
    return true;
}

bool Sandbox::Stop(uint32_t timeoutSecs, Errors &error)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->Stop(timeoutSecs, error);
    }
    return true;
}

bool Sandbox::Remove(Errors &error)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->Remove(error);
    }
    return true;
}
}