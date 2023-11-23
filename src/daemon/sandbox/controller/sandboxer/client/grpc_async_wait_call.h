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

#ifndef DAEMON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_GRPC_ASYNC_WAIT_CALL_H
#define DAEMON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_GRPC_ASYNC_WAIT_CALL_H

#include <string>

#include "sandbox.pb.h"
#include "sandbox.grpc.pb.h"

#include "controller.h"

namespace sandbox {

enum SandboxerAsyncWaitStatus {
    SANDBOXER_ASYNC_WAIT_STATUS_OK = 0,
    SANDBOXER_ASYNC_WAIT_STATUS_RETRY,
    SANDBOXER_ASYNC_WAIT_STATUS_NOT_FOUND,
    SANDBOXER_ASYNC_WAIT_STATUS_ERROR,
};

/**
 * SandboxerAsyncWaitCall is used to call the async wait method.
 * It will be passed to completion queue to wait for the response.
 * When the response is received, HandleResponse will be called.
 */
class SandboxerAsyncWaitCall {
public:
    SandboxerAsyncWaitCall(std::shared_ptr<SandboxStatusCallback> cb,
                           const std::string &sandboxId, const std::string &sandboxer);
    virtual ~SandboxerAsyncWaitCall() = default;
    auto Call(containerd::services::sandbox::v1::Controller::StubInterface &stub, grpc::CompletionQueue &cq) -> bool;
    auto HandleResponse() -> SandboxerAsyncWaitStatus;
    auto Timeout() -> bool;
    void SandboxExitCallback(bool statusOK, const ControllerExitInfo &exitInfo);
    void SandboxPendingCallback();
    void SandboxReadyCallback();
    auto GetSandboxId() -> const std::string &;
    auto MarkRemove() -> void
    {
        m_remove = true;
    }
    auto ToRemove() -> bool
    {
        return m_remove;
    }
    auto ResetRetryTimes() -> void
    {
        m_retryTimes = 0;
    }

protected:
    std::shared_ptr<containerd::services::sandbox::v1::Controller::StubInterface> m_stub;
    std::shared_ptr<SandboxStatusCallback> m_cb;
    std::string m_sandboxId;
    std::string m_sandboxer;
    std::unique_ptr<grpc::ClientAsyncResponseReaderInterface<containerd::services::sandbox::v1::ControllerWaitResponse>>
                                                                                                                      m_responseReader;
    std::unique_ptr<grpc::ClientContext> m_context;
    containerd::services::sandbox::v1::ControllerWaitResponse m_response;
    grpc::Status m_status;
    uint32_t m_retryTimes;
    uint64_t m_retryCounter;
    // The Call object will be deleted when it is unable to be enqueued to completion queue.
    // However, since gRPC call happens in async function in Future object, there is potential race condition
    // when deleting the call object:
    // 1. Monitor thread cleanup future object first, which holding the reference to call object, and
    //    then AysncCompletionRpcThread received response for the call later, and delete the call object.
    //    It is OK in this case, since future release the call ownership, and the call object deleted later.
    // 2. AsyncCompletionRpcThread received response for the call first, and delete the call object, and
    //    then Monitor thread cleanup future object later, which could cause use-after-free, since monitor
    //    thread will use the call to call the callback when cleaning the future object.
    // So we need to mark the call object as removed, cleanup them together in Monitor thread after checking
    // the future objects.
    bool m_remove;
};


}; // namespace sandbox

#endif // DAEMON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_GRPC_ASYNC_WAIT_CALL_H