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

#include "grpc_async_wait_call_mock.h"

static std::shared_ptr<SandboxerAsyncWaitCallMock> g_sandboxer_async_wait_call_mock = NULL;

void MockSandboxerAsyncWaitCall_SetMock(std::shared_ptr<SandboxerAsyncWaitCallMock> mock)
{
    g_sandboxer_async_wait_call_mock = mock;
}

SandboxerAsyncWaitCall::SandboxerAsyncWaitCall(std::shared_ptr<SandboxStatusCallback> cb,
                                               const std::string &sandboxId, const std::string &sandboxer)
{
    m_cb = cb;
    m_sandboxId = sandboxId;
    m_sandboxer = sandboxer;
    m_status = grpc::Status::OK;
    m_retryTimes = 0;
    m_retryCounter = 0;
    m_remove = false;
}

auto SandboxerAsyncWaitCall::Call(containerd::services::sandbox::v1::Controller::StubInterface &stub,
                                  grpc::CompletionQueue &cq) -> bool
{
    if (g_sandboxer_async_wait_call_mock == NULL) {
        return true;
    }
    return g_sandboxer_async_wait_call_mock->Call(stub, cq);
}

auto SandboxerAsyncWaitCall::HandleResponse() -> SandboxerAsyncWaitStatus
{
    if (g_sandboxer_async_wait_call_mock == NULL) {
        return SANDBOXER_ASYNC_WAIT_STATUS_OK;
    }
    return g_sandboxer_async_wait_call_mock->HandleResponse();
}

auto SandboxerAsyncWaitCall::Timeout() -> bool
{
    if (g_sandboxer_async_wait_call_mock == NULL) {
        return true;
    }
    return g_sandboxer_async_wait_call_mock->Timeout();
}

void SandboxerAsyncWaitCall::SandboxExitCallback(bool statusOK, const ControllerExitInfo &exitInfo)
{
    if (g_sandboxer_async_wait_call_mock == NULL) {
        return;
    }
    return g_sandboxer_async_wait_call_mock->SandboxExitCallback(statusOK, exitInfo);
}

void SandboxerAsyncWaitCall::SandboxPendingCallback()
{
    if (g_sandboxer_async_wait_call_mock == NULL) {
        return;
    }
    return g_sandboxer_async_wait_call_mock->SandboxPendingCallback();
}

void SandboxerAsyncWaitCall::SandboxReadyCallback()
{
    if (g_sandboxer_async_wait_call_mock == NULL) {
        return;
    }
    return g_sandboxer_async_wait_call_mock->SandboxReadyCallback();
}

auto SandboxerAsyncWaitCall::GetSandboxId() -> const std::string &
{
    if (g_sandboxer_async_wait_call_mock == NULL) {
        return m_sandboxId;
    }
    return g_sandboxer_async_wait_call_mock->GetSandboxId();
}
