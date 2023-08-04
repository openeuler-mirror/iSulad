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

#ifndef _ISULAD_TEST_MOCKS_GRPC_SANDBOXER_CLIENT_MOCK_H
#define _ISULAD_TEST_MOCKS_GRPC_SANDBOXER_CLIENT_MOCK_H

#include <gmock/gmock.h>
#include "grpc_sandboxer_client.h"
using namespace sandbox;

class SandboxerClientMock {
public:
    SandboxerClientMock() = default;
    MOCK_METHOD1(Init, void(Errors &error));
    MOCK_METHOD0(Destroy, void());
    MOCK_METHOD3(Create, bool(const std::string &sandboxId, const ControllerCreateParams &params, Errors &error));
    MOCK_METHOD3(Start, bool(const std::string &sandboxId, ControllerSandboxInfo &sandboxInfo, Errors &error));
    MOCK_METHOD3(Platform, bool(const std::string &sandboxId, ControllerPlatformInfo &platformInfo, Errors &error));
    MOCK_METHOD4(Prepare, bool(const std::string &sandboxId, const ControllerPrepareParams &params, std::string &bundle, Errors &error));
    MOCK_METHOD4(Purge, bool(const std::string &sandboxId, const std::string &containerId, const std::string &execId, Errors &error));
    MOCK_METHOD3(UpdateResources, bool(const std::string &sandboxId, const ControllerUpdateResourcesParams &params, Errors &error));
    MOCK_METHOD3(Stop, bool(const std::string &sandboxId, uint32_t timeoutSecs, Errors &error));
    MOCK_METHOD3(Wait, bool(std::shared_ptr<SandboxStatusCallback> cb, const std::string &sandboxId, Errors &error));
    MOCK_METHOD4(Status, bool(const std::string &sandboxId, bool verbose, ControllerSandboxStatus &sandboxStatus, Errors &error));
    MOCK_METHOD2(Shutdown, bool(const std::string &sandboxId, Errors &error));
};

void MockSandboxerClient_SetMock(std::shared_ptr<SandboxerClientMock> mock);

#endif // _ISULAD_TEST_MOCKS_GRPC_SANDBOXER_CLIENT_MOCK_H
