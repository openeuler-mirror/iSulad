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
 * Create: 2023-07-31
 * Description: provide grpc sandboxer async wait call mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_GRPC_SANDBOXER_ASYNC_WAIT_CALL_MOCK_H
#define _ISULAD_TEST_MOCKS_GRPC_SANDBOXER_ASYNC_WAIT_CALL_MOCK_H

#include <gmock/gmock.h>
#include "grpc_async_wait_call.h"
using namespace sandbox;

// Mock above class
class SandboxerAsyncWaitCallMock {
public:
    MOCK_METHOD2(Call, bool(containerd::services::sandbox::v1::Controller::StubInterface &stub, grpc::CompletionQueue &cq));
    MOCK_METHOD0(HandleResponse, SandboxerAsyncWaitStatus());
    MOCK_METHOD0(Timeout, bool());
    MOCK_METHOD2(SandboxExitCallback, void(bool statusOK, const ControllerExitInfo &exitInfo));
    MOCK_METHOD0(SandboxPendingCallback, void());
    MOCK_METHOD0(SandboxReadyCallback, void());
    MOCK_METHOD0(GetSandboxId, const std::string &());
};

void MockSandboxerAsyncWaitCall_SetMock(std::shared_ptr<SandboxerAsyncWaitCallMock> mock);

#endif // _ISULAD_TEST_MOCKS_GRPC_SANDBOXER_ASYNC_WAIT_CALL_MOCK_H