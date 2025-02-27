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

#ifdef ENABLE_SANDBOXER

#include <gmock/gmock.h>
#include "sandboxer_sandbox_mock.h"

namespace sandbox {
MockSandboxerSandbox *g_sandboxer_sandbox_mock = nullptr;

SandboxerSandbox::SandboxerSandbox(const std::string id, const std::string &rootdir, const std::string &statedir, const std::string name,
                 const RuntimeInfo info, std::string netMode, std::string netNsPath, const runtime::v1::PodSandboxConfig sandboxConfig,
                 std::string image):Sandbox(id, rootdir, statedir, name, info, netMode,
					 								  netNsPath, sandboxConfig, image)
{
}

void MockSandboxerSandbox_SetMock(MockSandboxerSandbox *mock)
{
    g_sandboxer_sandbox_mock = mock;
}

void SandboxerSandbox::LoadSandboxTasks() {}

auto SandboxerSandbox::PrepareContainer(const char *containerId, const char *baseFs,
                               const oci_runtime_spec *ociSpec,
                               const char *consoleFifos[]) -> int
{
    if (g_sandboxer_sandbox_mock != nullptr) {
        return g_sandboxer_sandbox_mock->PrepareContainer(containerId, baseFs, ociSpec, consoleFifos);
    }
    return 0;
}   

auto SandboxerSandbox::PrepareExec(const char *containerId, const char *execId,
                          defs_process *processSpec, const char *consoleFifos[]) -> int
{
    if (g_sandboxer_sandbox_mock != nullptr) {
        return g_sandboxer_sandbox_mock->PrepareExec(containerId, execId, processSpec, consoleFifos);
    }
    return 0;
}   

auto SandboxerSandbox::PurgeContainer(const char *containerId) -> int
{
    if (g_sandboxer_sandbox_mock != nullptr) {
        return g_sandboxer_sandbox_mock->PurgeContainer(containerId);
    }
    return 0;
}

auto SandboxerSandbox::PurgeExec(const char *containerId, const char *execId) -> int
{
    if (g_sandboxer_sandbox_mock != nullptr) {
        return g_sandboxer_sandbox_mock->PurgeExec(containerId, execId);
    }
    return 0;
}

}
#endif