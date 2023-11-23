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
 * Description: Sandboxer grpc client monitor
 ******************************************************************************/

#ifndef DAEMON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_GRPC_SANDBOXER_MONITOR_H
#define DAEMON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_GRPC_SANDBOXER_MONITOR_H

#include <memory>
#include <string>
#include <thread>
#include <future>

#include "grpc_async_wait_call.h"

namespace sandbox {

/**
 * SandboxerClientMonitor is used to monitor the async wait call.
 * It will start two threads, one for monitoring the completion queue,
 * the other for retrying the async wait call.
 * The lifecycle of SandboxerAsyncWaitCall object is managed in the following way:
 * 1. When the async call first called, it will be directly passed into completion queue.
 * 2. If the call status received from completion queue is SANDBOXER_ASYNC_WAIT_STATUS_RETRY,
 *    the call will be enqueued to m_deferredCalls, otherwise it will be deleted.
 * 3. When the deferred duration is reached for the call, it will be retried, and passed to
 *    completion queue again.
 */
class SandboxerClientMonitor {
public:
    SandboxerClientMonitor(std::shared_ptr<grpc::Channel> channel, const std::string &sandboxer);
    ~SandboxerClientMonitor() = default;

    auto Monitor(SandboxerAsyncWaitCall *call) -> bool;
    void Start();
    void Stop();
private:
    auto IsAlive() -> bool;
    void AddDeferredCall(SandboxerAsyncWaitCall *call);
    void WaitForDeferredCall();
    void InvokeDeferredCall(SandboxerAsyncWaitCall *call);
    void DispatchDeferredCalls();
    void AsyncCompleteRpcThread();
    void MonitorThread();
    void CheckCompletedFutures();
    void DeleteRemovedCalls();
    void ClearDeferredCalls();
    void ClearAllCalls();
    void Cleanup();

    std::thread m_cqThread;
    std::thread m_deferredThread;
    std::unique_ptr<containerd::services::sandbox::v1::Controller::StubInterface> m_stub;
    std::shared_ptr<grpc::Channel> m_channel;
    std::string m_sandboxer;
    // Completion queue is thread safe, no mutex needed
    grpc::CompletionQueue m_cq;
    // Vector for holding all the calls for monitoring
    std::vector<SandboxerAsyncWaitCall *> m_calls;
    std::mutex m_callsMutex;
    // Use to indicate whether
    bool m_teardown;
    // Vector for holding all the retry calls
    std::vector<SandboxerAsyncWaitCall *> m_deferredCalls;
    std::mutex m_deferredCallsMutex;
    std::condition_variable m_deferredCallsCond;

    // Vector for holding all the futures in flight
    // No need to lock, only used in m_deferredThread thread
    std::vector<std::future<std::pair<bool, SandboxerAsyncWaitCall*>>> m_futures;
};

} // namespace sandbox

#endif // DAEMON_SANDBOX_CONTROLLER_SANDBOXER_CLIENT_GRPC_SANDBOXER_MONITOR_H