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

#include "grpc_sandboxer_monitor.h"

#include <random>

#include "isula_libutils/log.h"

namespace sandbox {

const int64_t DEFERRED_QUEUE_CHECK_INTERVAL = 200; // milliseconds

SandboxerClientMonitor::SandboxerClientMonitor(std::shared_ptr<grpc::Channel> channel, const std::string &sandboxer):
    m_channel(channel), m_sandboxer(sandboxer), m_teardown(false)
{
    m_stub = containerd::services::sandbox::v1::Controller::NewStub(m_channel);
}

// Monitor will gain the ownership of the call object, and is responsible
// for deleting it
auto SandboxerClientMonitor::Monitor(SandboxerAsyncWaitCall *call) -> bool
{
    if (call == nullptr) {
        ERROR("Async wait call is null, failed to monitor.");
        return false;
    }

    if (m_teardown) {
        ERROR("Monitor is already shutdown, failed to monitor sandbox, id: %s",
              call->GetSandboxId().c_str());
        delete call;
        return false;
    }

    // Try to monitor the call, if failed, we should delete it right way
    if (!call->Call(*m_stub, m_cq)) {
        // The failure is most likely due to the fact that the completion queue is shutdown
        delete call;
        return false;
    }
    // The call will be enqueued into completion queue, and the callback
    // will be invoked when the response is ready
    std::unique_lock<std::mutex> lock(m_callsMutex);
    m_calls.push_back(call);
    INFO("Start to monitor sandboxer wait call, sandbox id: %s",
         call->GetSandboxId().c_str());
    return true;
}

void SandboxerClientMonitor::Start()
{
    m_cqThread = std::thread(&SandboxerClientMonitor::AsyncCompleteRpcThread, this);
    m_deferredThread = std::thread(&SandboxerClientMonitor::MonitorThread, this);
}

void SandboxerClientMonitor::Stop()
{
    // At the time of shutdown, the calls objects are in three states:
    // 1. In the completion queue, waiting for the response
    // 2. In the deferred queue, waiting for the dispatch
    // 3. In the future queue, are about to get into completion queue
    // We should cleanup all those objects
    m_cq.Shutdown();
    m_teardown = true;
    // In case the deferred queue is empty, we should notify the condition variable
    m_deferredCallsCond.notify_one();
    INFO("Stopping sandboxer wait call monitor, sandboxer: %s", m_sandboxer.c_str());
    // Wait until all the threads exit
    m_cqThread.join();
    m_deferredThread.join();
}

auto SandboxerClientMonitor::IsAlive() -> bool
{
    // GetState will retry the channel connection if channel is not active when the parameter is true.
    // Monitor will keep retrying with wait call, so we dont have to let channel reconnect here, use false instead.
    return m_channel->GetState(false) == GRPC_CHANNEL_READY;
}

// When the call needs to be retried, we should put it into the deferred queue
void SandboxerClientMonitor::AddDeferredCall(SandboxerAsyncWaitCall *call)
{
    std::unique_lock<std::mutex> lock(m_deferredCallsMutex);
    m_deferredCalls.push_back(call);
    m_deferredCallsCond.notify_one();
}

// When the deferred queue and future queue are empty, we should wait for the condition signal
void SandboxerClientMonitor::WaitForDeferredCall()
{
    std::unique_lock<std::mutex> lock(m_deferredCallsMutex);
    // Check m_futures queue here as well just in case m_futures queue is
    if (m_deferredCalls.empty() && m_futures.empty() && !m_teardown) {
        m_deferredCallsCond.wait(lock);
    }
}

// Retry the call after a random sleep time
// There are two return values for the future:
// 1. bool: Indicate the call has been successfully retried and enqueued into completion queue
// 2. SandboxerAsyncWaitCall *: The call handled by the future
void SandboxerClientMonitor::InvokeDeferredCall(SandboxerAsyncWaitCall *call)
{
    m_futures.push_back(std::async([this, call]() {
        // Random sleep for 50 ~ 200 milliseconds to avoid thundering herd
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(DEFERRED_QUEUE_CHECK_INTERVAL / 4, DEFERRED_QUEUE_CHECK_INTERVAL);
        int sleepTime = dis(gen);
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));

        if (this->m_teardown) {
            // If the monitor is already shutdown, the call will be cleaned up
            // by the cleanup function
            return std::pair<bool, SandboxerAsyncWaitCall*>(false, nullptr);
        }
        if (!call->Call(*m_stub, m_cq)) {
            return std::pair<bool, SandboxerAsyncWaitCall*>(false, call);
        }
        return std::pair<bool, SandboxerAsyncWaitCall*>(true, call);
    }));
}

// Iterate the calls that are timeout and retry them
void SandboxerClientMonitor::DispatchDeferredCalls()
{
    std::unique_lock<std::mutex> lock(m_deferredCallsMutex);
    if (m_teardown) {
        // Stop dispatching deferred calls
        return;
    }
    for (auto it = m_deferredCalls.begin(); it != m_deferredCalls.end();) {
        auto &call = (*it);
        if (call->Timeout()) {
            // If the call is timeout, we should retry
            InvokeDeferredCall(call);
            it = m_deferredCalls.erase(it);
        } else {
            it++;
        }
    }
}

// We use future to invoke the deferred call, when the future is ready, we should check the result
void SandboxerClientMonitor::CheckCompletedFutures()
{
    for (auto it = m_futures.begin(); it != m_futures.end();) {
        auto &future = (*it);
        if (future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            auto result = future.get();
            auto enqueued = result.first;
            auto call = result.second;
            if (!enqueued) {
                if (call != nullptr) {
                    // Sandbox has been notified due to call failure in call->Call,
                    // so no need to notify again
                    call->MarkRemove();
                }
            } else {
                // When the async wait is enqueued into completion queue,
                // and wait does not return error, we have no feadback
                // from the sandboxer, since async wait only return when
                // sandbox exited or some errors happened.
                // Therefore, one way to assume that the wait call suceeded
                // is that check the client status. If the client goes alive,
                // we assume the wait call succeeded.
                if (IsAlive()) {
                    // The future is responsible to enqueue the call
                    // into completion queue. So there is still a chance
                    // that before we check future status here,
                    // the call in completion queue has already finished,
                    // and the callback has been invoked with OnSandboxPending
                    // or OnSandboxExit in the HandleResponse function.
                    // In this case, the OnSandboxReady will overwrite the
                    // status, but it is ok, because:
                    // 1. If OnSandboxPending has been invoked,
                    //    retry will happen pretty soon, and the
                    //    callback will be invoked again.
                    // 2. If OnSandboxExit has been invoked, the caller
                    //    should check the sandbox status in the OnSandboxReady
                    //    callback, and it will find out the sandbox has exited,
                    //    and not set sandbox to ready status.
                    call->SandboxReadyCallback();
                    call->ResetRetryTimes();
                }
            }
            it = m_futures.erase(it);
        } else {
            it++;
        }
    }
}

void SandboxerClientMonitor::ClearDeferredCalls()
{
    std::unique_lock<std::mutex> lock(m_deferredCallsMutex);
    m_deferredCalls.clear();
}

void SandboxerClientMonitor::ClearAllCalls()
{
    std::unique_lock<std::mutex> lock(m_callsMutex);
    for (auto &call : m_calls) {
        delete call;
    }
    m_calls.clear();
}

void SandboxerClientMonitor::Cleanup()
{
    for (auto &future : m_futures) {
        future.wait();
    }
    m_futures.clear();
    ClearDeferredCalls();
    ClearAllCalls();
}

/**
 * Thread for handling completion queue.
 */
void SandboxerClientMonitor::AsyncCompleteRpcThread()
{
    void *got_tag;
    bool ok = false;
    SandboxerAsyncWaitStatus waitStatus;
    INFO("Start thread to monitor wait call completion queue for sandboxer, sandboxer: %s",
         m_sandboxer.c_str());

    pthread_setname_np(pthread_self(), "SandboxerAsyncWaitThread");

    // Next only return false when the completion queue is shutdown and
    // the queue is fully drained
    while (m_cq.Next(&got_tag, &ok)) {
        if (got_tag == nullptr || m_teardown) {
            // The completion queue is shutdown
            // The calls will be cleaned up by the cleanup function
            break;
        }
        auto call = static_cast<SandboxerAsyncWaitCall *>(got_tag);
        waitStatus = call->HandleResponse();
        if (waitStatus == SANDBOXER_ASYNC_WAIT_STATUS_RETRY) {
            AddDeferredCall(call);
            continue;
        }
        // The reason for not deleting the call here is that
        // while the call is being handled in this thread,
        // the call object could still possibly be referenced in the future
        // that has not been checked yet by the monitor thread. This could happen
        // especially when the completion queue is shutdown.
        call->MarkRemove();
        // Should notify deferred thread to clean up the call
        m_deferredCallsCond.notify_one();
    }
    INFO("Completion queue is shutdown, wait call monitor thread exit for sandboxer: %s",
         m_sandboxer.c_str());
}

/**
 * Delete the calls that are marked to be removed.
 */
void SandboxerClientMonitor::DeleteRemovedCalls()
{
    std::unique_lock<std::mutex> lock(m_callsMutex);
    for (auto it = m_calls.begin(); it != m_calls.end();) {
        auto &call = (*it);
        if (call->ToRemove()) {
            delete call;
            it = m_calls.erase(it);
        } else {
            it++;
        }
    }
}

/**
 * Thread for handling deferred retry calls and cleanup.
 */
void SandboxerClientMonitor::MonitorThread()
{
    INFO("Start wait call monitoring thread, sandboxer: %s",
         m_sandboxer.c_str());
    pthread_setname_np(pthread_self(), "SandboxerMonitorThread");
    while (!m_teardown) {
        // 1. Clean up futures that are ready
        CheckCompletedFutures();
        // 2. Delete the calls that are marked to be removed
        DeleteRemovedCalls();
        // 3. If deferred queue is empty, wait for the condition signal
        WaitForDeferredCall();
        // 4. We have deferred calls in the queue, deferred for 200 ms
        std::this_thread::sleep_for(std::chrono::milliseconds(DEFERRED_QUEUE_CHECK_INTERVAL));
        // 5. Dispatch the deferred calls
        DispatchDeferredCalls();
    }
    // Cleanup the queue
    Cleanup();
    INFO("Start wait call monitoring thread, sandboxer: %s", m_sandboxer.c_str());
}

} // namespace sandbox