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

#include "sandbox_manager_mock.h"

namespace sandbox {
static std::shared_ptr<MockSandboxManager> g_sandbox_manager_mock = nullptr;

void MockSandboxManager_SetMock(std::shared_ptr<MockSandboxManager> mock)
{
    g_sandbox_manager_mock = mock;
}

SandboxManager *SandboxManager::GetInstance() noexcept
{
    if (g_sandbox_manager_mock != nullptr) {
        return g_sandbox_manager_mock->GetInstance();
    }
    return nullptr;
}

std::shared_ptr<Sandbox> SandboxManager::GetSandbox(const std::string &idOrName)
{
    if (g_sandbox_manager_mock != nullptr) {
        return g_sandbox_manager_mock->GetSandbox(idOrName);
    }
    return nullptr;
}

}
