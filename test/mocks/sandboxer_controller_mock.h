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

#ifndef _ISULAD_TEST_MOCKS_SANDBOXER_CONTROLLER_MOCK_H
#define _ISULAD_TEST_MOCKS_SANDBOXER_CONTROLLER_MOCK_H

#include <gmock/gmock.h>
#include <memory>

#include "sandboxer_controller.h"

namespace sandbox {

class MockSandboxerController {
public:
    MockSandboxerController() = default;
    virtual ~MockSandboxerController() = default;

    MOCK_METHOD1(Init, bool(Errors &error));
    MOCK_METHOD3(Create, bool(const std::string &sandboxId,
                              const ControllerCreateParams &params,
                              Errors &error));
    MOCK_METHOD2(Start, std::unique_ptr<ControllerSandboxInfo>(const std::string &sandboxId, Errors &error));
    MOCK_METHOD2(Platform, std::unique_ptr<ControllerPlatformInfo>(const std::string &sandboxId, Errors &error));
    MOCK_METHOD3(Update, bool(sandbox_sandbox *apiSandbox,
                            string_array *fields, Errors &error));
    MOCK_METHOD3(Stop, bool(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error));
    MOCK_METHOD3(Wait, bool(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error));
    MOCK_METHOD3(Status, std::unique_ptr<ControllerSandboxStatus>(const std::string &sandboxId, bool verbose,
                                                                  Errors &error));
    MOCK_METHOD2(Shutdown, bool(const std::string &sandboxId, Errors &error));
    MOCK_METHOD3(UpdateNetworkSettings, bool(const std::string &sandboxId, const std::string &networkSettings,
                                             Errors &error));
};

void MockSandboxerController_SetMock(std::shared_ptr<MockSandboxerController> mock);

}

#endif