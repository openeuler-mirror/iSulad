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
 * Create: 2023-07-28
 * Description: gRPC Async wait call object
 ******************************************************************************/

#include "grpc_async_wait_call.h"

#include <grpc++/grpc++.h>
#include <isula_libutils/log.h>

#include "grpc_client_utils.h"

namespace sandbox {

// Max retry counter. In monitor thread, we will check deferred calls every 200ms
// so if a call has retry counter for 1500, it means the call will be retried after 300 seconds
const int64_t MAX_RETRY_COUNTER = 1500; // 1500 * 200ms = 300s

SandboxerAsyncWaitCall::SandboxerAsyncWaitCall(std::shared_ptr<SandboxStatusCallback> cb,
                                               const std::string &sandboxId, const std::string &sandboxer)
    : m_cb(cb), m_sandboxId(sandboxId), m_sandboxer(sandboxer)
{
    m_status = grpc::Status::OK;
    m_retryTimes = 0;
    m_retryCounter = 0;
    m_remove = false;
}

auto SandboxerAsyncWaitCall::Call(containerd::services::sandbox::v1::Controller::StubInterface &stub, grpc::CompletionQueue &cq) -> bool
{
    containerd::services::sandbox::v1::ControllerWaitRequest request;
    m_context = std::unique_ptr<grpc::ClientContext>(new grpc::ClientContext());
    request.set_sandboxer(m_sandboxer);
    request.set_sandbox_id(m_sandboxId);
    m_responseReader = stub.PrepareAsyncWait(m_context.get(), request, &cq);
    if (m_responseReader == nullptr) {
        // Most likely the completion queue is shutdown
        ERROR("Failed to prepare async wait request for sandboxer wait request, sandbox id: %s", m_sandboxId.c_str());
        SandboxExitCallback(false, ControllerExitInfo());
        return false;
    }
    m_responseReader->StartCall();
    m_responseReader->Finish(&m_response, &m_status, (void *)this);
    return true;
}

auto SandboxerAsyncWaitCall::SandboxExitCallback(bool statusOK, const ControllerExitInfo &exitInfo) -> void
{
    // If statusOK is false, it means something unexpected happened during async wait,
    // the exitInfo is not valid, but we assume that the sandbox has exited.
    if (!statusOK) {
        ControllerExitInfo info;
        auto currentTime = std::chrono::high_resolution_clock::now();
        auto duration = currentTime.time_since_epoch();
        info.exitedAt = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
        info.exitStatus = -1;
        m_cb->OnSandboxExit(info);
        return;
    }
    m_cb->OnSandboxExit(exitInfo);
}

auto SandboxerAsyncWaitCall::SandboxPendingCallback() -> void
{
    m_cb->OnSandboxPending();
}

auto SandboxerAsyncWaitCall::SandboxReadyCallback() -> void
{
    m_cb->OnSandboxReady();
}

auto SandboxerAsyncWaitCall::Timeout() -> bool
{
    m_retryCounter--;
    return m_retryCounter == 0;
}

auto SandboxerAsyncWaitCall::GetSandboxId() -> const std::string &
{
    return m_sandboxId;
}

SandboxerAsyncWaitStatus SandboxerAsyncWaitCall::HandleResponse()
{
    ControllerExitInfo exitInfo;
    SandboxerAsyncWaitStatus waitStatus = SANDBOXER_ASYNC_WAIT_STATUS_ERROR;

    switch(m_status.error_code()) {
        case grpc::StatusCode::UNAVAILABLE:
            // If the status is unavailable, connection failed, we should retry
            WARN("Sandboxer controller wait rpc server unavailable, error_code: %d: %s", m_status.error_code(), m_status.error_message().c_str());
            waitStatus = SANDBOXER_ASYNC_WAIT_STATUS_RETRY;
            m_retryTimes++;
            // If retried times is more than 10, we should retry every 300 seconds
            if (m_retryTimes > 10) {
                m_retryCounter = MAX_RETRY_COUNTER;
            } else {
                // Retry interval is 2 ^ retry times
                m_retryCounter = 1 << m_retryTimes;
            }
            m_cb->OnSandboxPending();
            break;
        case grpc::StatusCode::OK:
            exitInfo.exitedAt = TimestampToNanos(m_response.exited_at());
            exitInfo.exitStatus = m_response.exit_status();
            DEBUG("Sandboxer controller wait request success, sandbox id: %s, exit status: %d, exited at: %lu",
                  m_sandboxId.c_str(), exitInfo.exitStatus, exitInfo.exitedAt);
            SandboxExitCallback(true, exitInfo);
            waitStatus = SANDBOXER_ASYNC_WAIT_STATUS_OK;
            break;
        case grpc::StatusCode::NOT_FOUND:
            // If the sandbox is not found, it has been deleted, we should return not found
            WARN("The sandbox wait doesn't exist, sandbox id: %s, error_code: %d: %s",
                 m_sandboxId.c_str(), m_status.error_code(), m_status.error_message().c_str());
            waitStatus = SANDBOXER_ASYNC_WAIT_STATUS_NOT_FOUND;
            SandboxExitCallback(false, exitInfo);
            break;
        default:
            // TODO: More error code should be handled
            ERROR("Sandboxer controller wait request failed, error_code: %d: %s", m_status.error_code(), m_status.error_message().c_str());
            SandboxExitCallback(false, exitInfo);
            break;
    }

    return waitStatus;
}

}; // namespace sandbox