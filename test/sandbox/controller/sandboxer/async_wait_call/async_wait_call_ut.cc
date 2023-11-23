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
 * Description: Async wait call UT
 ******************************************************************************/

#include "gtest/gtest.h"
#include "grpc_async_wait_call.h"
#include "dummy_monitor_utils.h"
#include "controller_stub_mock.h"
#include "grpc_client_utils.h"
#include "controller.h"

class SandboxerAsyncWaitCallWrapper : public sandbox::SandboxerAsyncWaitCall {
public:
    SandboxerAsyncWaitCallWrapper(std::shared_ptr<sandbox::SandboxStatusCallback> cb,
                                  const std::string &sandboxId, const std::string &sandboxer)
        : sandbox::SandboxerAsyncWaitCall(cb, sandboxId, sandboxer) {}
    ~SandboxerAsyncWaitCallWrapper() = default;

    grpc::ClientAsyncResponseReaderInterface<containerd::services::sandbox::v1::ControllerWaitResponse> &GetReader()
    {
        return *m_responseReader;
    }
};

class AsyncWaitCallTest : public testing::Test {
protected:
    void SetUp() override
    {
        m_sandboxId = "8040f13d54889ad4cd";
        m_sandboxer = "test_sandboxer";
        m_callback = std::shared_ptr<DummyCallback>(new DummyCallback());
        m_call = std::unique_ptr<sandbox::SandboxerAsyncWaitCall>(new sandbox::SandboxerAsyncWaitCall(m_callback, m_sandboxId,
                                                                                                      m_sandboxer));
        m_stub = std::unique_ptr<DummyControllerStub>(NewDummyControllerStub());
        m_stub_mock = std::make_shared<MockControllerStub>();
        MockControllerStub_SetMock(m_stub_mock);
    }

    void TearDown() override
    {
        MockControllerStub_SetMock(nullptr);
    }

    std::string m_sandboxId;
    std::string m_sandboxer;
    std::shared_ptr<DummyCallback> m_callback;
    std::unique_ptr<sandbox::SandboxerAsyncWaitCall> m_call;
    std::unique_ptr<DummyControllerStub> m_stub;
    std::shared_ptr<MockControllerStub> m_stub_mock;
    grpc::CompletionQueue m_cq;
};

TEST_F(AsyncWaitCallTest, CallStatusOK)
{
    auto reader = new DummyClientAsyncResponseReader();
    auto timestamp = google::protobuf::Timestamp();
    timestamp.set_seconds(123456);
    reader->SetExitAt(timestamp);
    reader->SetExitStatus(1);
    reader->SetStatus(grpc::Status::OK);
    EXPECT_CALL(*m_stub_mock, PrepareAsyncWaitRaw).WillOnce(testing::Return(reader));
    EXPECT_TRUE(m_call->Call(*m_stub, m_cq));
    EXPECT_EQ(m_call->HandleResponse(), sandbox::SANDBOXER_ASYNC_WAIT_STATUS_OK);
    EXPECT_EQ(m_callback->GetStatus(), ASYNC_WAIT_CALL_STATUS_EXIT);
    EXPECT_EQ(m_callback->GetExitStatus(), 1);
    EXPECT_EQ(m_callback->GetExitedAt(), TimestampToNanos(timestamp));
}

TEST_F(AsyncWaitCallTest, CallStatusError)
{
    auto reader = new DummyClientAsyncResponseReader();
    reader->SetStatus(grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Permission denied"));
    EXPECT_CALL(*m_stub_mock, PrepareAsyncWaitRaw).WillOnce(testing::Return(reader));
    EXPECT_TRUE(m_call->Call(*m_stub, m_cq));
    EXPECT_EQ(m_call->HandleResponse(), sandbox::SANDBOXER_ASYNC_WAIT_STATUS_ERROR);
    EXPECT_EQ(m_callback->GetStatus(), ASYNC_WAIT_CALL_STATUS_EXIT);
}

TEST_F(AsyncWaitCallTest, CallStatusNotFound)
{
    auto reader = new DummyClientAsyncResponseReader();
    reader->SetStatus(grpc::Status(grpc::StatusCode::NOT_FOUND, "Not found"));
    EXPECT_CALL(*m_stub_mock, PrepareAsyncWaitRaw).WillOnce(testing::Return(reader));
    EXPECT_TRUE(m_call->Call(*m_stub, m_cq));
    EXPECT_EQ(m_call->HandleResponse(), sandbox::SANDBOXER_ASYNC_WAIT_STATUS_NOT_FOUND);
    EXPECT_EQ(m_callback->GetStatus(), ASYNC_WAIT_CALL_STATUS_EXIT);
}

TEST_F(AsyncWaitCallTest, CallStatusUnavailable)
{
    auto reader = new DummyClientAsyncResponseReader();
    reader->SetStatus(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Unavailable"));
    EXPECT_CALL(*m_stub_mock, PrepareAsyncWaitRaw).WillOnce(testing::Return(reader));
    EXPECT_TRUE(m_call->Call(*m_stub, m_cq));
    EXPECT_EQ(m_call->HandleResponse(), sandbox::SANDBOXER_ASYNC_WAIT_STATUS_RETRY);
    EXPECT_EQ(m_callback->GetStatus(), ASYNC_WAIT_CALL_STATUS_PENDING);
}

TEST_F(AsyncWaitCallTest, CallStatusPrepareAsyncWaitFailed)
{
    EXPECT_CALL(*m_stub_mock, PrepareAsyncWaitRaw).WillOnce(testing::Return(nullptr));
    EXPECT_FALSE(m_call->Call(*m_stub, m_cq));
    EXPECT_EQ(m_callback->GetStatus(), ASYNC_WAIT_CALL_STATUS_EXIT);
}
