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
 * Author: liuxu
 * Create: 2024-11-21
 * Description: provide sandbox mock
 ******************************************************************************/

#include <gmock/gmock.h>
#include "shim_sandbox_mock.h"

namespace sandbox {
MockShimSandbox *g_shim_sandbox_mock = nullptr;

ShimSandbox::ShimSandbox(const std::string id, const std::string &rootdir, const std::string &statedir, const std::string name,
                 const RuntimeInfo info, std::string netMode, std::string netNsPath, const runtime::v1::PodSandboxConfig sandboxConfig,
                 std::string image):Sandbox(id, rootdir, statedir, name, info, netMode,
					 								  netNsPath, sandboxConfig, image)
{
}

void MockShimSandbox_SetMock(MockShimSandbox *mock)
{
    g_shim_sandbox_mock = mock;
}

void ShimSandbox::LoadSandboxTasks() {}

auto ShimSandbox::SaveSandboxTasks() -> bool
{
    if (g_shim_sandbox_mock != nullptr) {
        return g_shim_sandbox_mock->SaveSandboxTasks();
    }
    return true;
}

auto ShimSandbox::AddSandboxTasks(sandbox_task *task) -> bool
{
    if (g_shim_sandbox_mock != nullptr) {
        return g_shim_sandbox_mock->AddSandboxTasks(task);
    }
    return true;
}

auto ShimSandbox::GetAnySandboxTasks() -> std::string
{
    if (g_shim_sandbox_mock != nullptr) {
        return g_shim_sandbox_mock->GetAnySandboxTasks();
    }
    return std::string("Nothing for shim.");
}

void ShimSandbox::DeleteSandboxTasks(const char *containerId) {}

auto ShimSandbox::AddSandboxTasksProcess(const char *containerId, sandbox_process *processes) -> bool
{
    if (g_shim_sandbox_mock != nullptr) {
        return g_shim_sandbox_mock->AddSandboxTasksProcess(containerId, processes);
    }
   return true;
}

void ShimSandbox::DeleteSandboxTasksProcess(const char *containerId, const char *execId) {}

}