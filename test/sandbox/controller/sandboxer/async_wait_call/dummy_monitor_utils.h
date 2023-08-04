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
 * Create: 2023-08-01
 * Description: provide dummy class definition for monitor unit tests
 *********************************************************************************/

#ifndef DUMMY_MONITOR_UTILS_H_
#define DUMMY_MONITOR_UTILS_H_

#include "sandbox.pb.h"
#include "sandbox.grpc.pb.h"

#include "controller.h"

class DummyClientAsyncResponseReader: public grpc::ClientAsyncResponseReaderInterface<containerd::services::sandbox::v1::ControllerWaitResponse> {
public:
    DummyClientAsyncResponseReader() = default;
    ~DummyClientAsyncResponseReader() = default;

    void StartCall() override {}

    void ReadInitialMetadata(void *tag) override {}

    void Finish(containerd::services::sandbox::v1::ControllerWaitResponse *response, grpc::Status *status, void *tag) override {
        response->set_exit_status(m_exitStatus);
        response->mutable_exited_at()->CopyFrom(m_exitedAt);
        *status = m_status;
        m_tag = tag;
    }

    void SetExitAt(const google::protobuf::Timestamp &exitAt) {
        m_exitedAt = exitAt;
    }

    void SetExitStatus(uint32_t status) {
        m_exitStatus = status;
    }

    void SetStatus(grpc::Status status) {
        m_status = status;
    }

    void *GetTag() {
        return m_tag;
    }

private:
    google::protobuf::Timestamp m_exitedAt;
    uint32_t m_exitStatus;
    containerd::services::sandbox::v1::ControllerWaitResponse *m_response;
    grpc::Status m_status;
    void *m_tag;
};

enum AsyncWaitCallStatus {
    ASYNC_WAIT_CALL_STATUS_UNKNOWN,
    ASYNC_WAIT_CALL_STATUS_READY,
    ASYNC_WAIT_CALL_STATUS_EXIT,
    ASYNC_WAIT_CALL_STATUS_PENDING,
};

class DummyCallback: public sandbox::SandboxStatusCallback {
public:
    DummyCallback() {
        m_status = ASYNC_WAIT_CALL_STATUS_UNKNOWN;
    }
    ~DummyCallback() = default;

    void OnSandboxReady() override { m_status = ASYNC_WAIT_CALL_STATUS_READY; }
    void OnSandboxPending() override { m_status = ASYNC_WAIT_CALL_STATUS_PENDING; }
    void OnSandboxExit(const sandbox::ControllerExitInfo &exitInfo) override {
        m_status = ASYNC_WAIT_CALL_STATUS_EXIT;
        m_exitStatus = exitInfo.exitStatus;
        m_exitedAt = exitInfo.exitedAt;
    }

    AsyncWaitCallStatus GetStatus() {
        return m_status;
    }

    uint32_t GetExitStatus() {
        return m_exitStatus;
    }

    uint64_t GetExitedAt() {
        return m_exitedAt;
    }
private:
    AsyncWaitCallStatus m_status;
    uint32_t m_exitStatus;
    uint64_t m_exitedAt;
};

#endif // DUMMY_MONITOR_UTILS_H_