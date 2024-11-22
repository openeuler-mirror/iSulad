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
 * Description: provide sandbox manager mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_SANDBOX_MANAGER_MOCK_H
#define _ISULAD_TEST_MOCKS_SANDBOX_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include <memory>

#include "sandbox.h"
#include "sandbox_manager.h"

namespace sandbox {

class MockSandboxManager {
public:
    MockSandboxManager() = default;
    virtual ~MockSandboxManager() = default;

    MOCK_METHOD0(GetInstance, SandboxManager *());

    MOCK_METHOD1(GetSandbox, std::shared_ptr<Sandbox>(const std::string &idOrName));
    
};

void MockSandboxManager_SetMock(std::shared_ptr<MockSandboxManager> mock);

}

#endif