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

#ifndef _ISULAD_TEST_MOCKS_SHIM_SANDBOX_MOCK_H
#define _ISULAD_TEST_MOCKS_SHIM_SANDBOX_MOCK_H

#include <gmock/gmock.h>
#include "sandbox_mock.h"
#include "shim_sandbox.h"

namespace sandbox {

class MockShimSandbox : public MockSandbox {
public:
    MockShimSandbox() = default;
    virtual ~MockShimSandbox() = default;

    MOCK_METHOD0(LoadSandboxTasks, void());
    MOCK_METHOD0(SaveSandboxTasks, bool());
    MOCK_METHOD1(AddSandboxTasks, bool(sandbox_task *task));
    MOCK_METHOD0(GetAnySandboxTasks, std::string());
    MOCK_METHOD1(DeleteSandboxTasks, void(const char *containerId));
    MOCK_METHOD2(AddSandboxTasksProcess, bool(const char *containerId, sandbox_process *processes));
    MOCK_METHOD2(DeleteSandboxTasksProcess, void(const char *containerId, const char *execId));
};

void MockShimSandbox_SetMock(MockShimSandbox *mock);

}

#endif
