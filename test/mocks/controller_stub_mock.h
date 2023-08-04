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
 * Description: provide grpc controller stub mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_CONTROLLER_STUB_MOCK_H
#define _ISULAD_TEST_MOCKS_CONTROLLER_STUB_MOCK_H


#include <gmock/gmock.h>
#include "sandbox.grpc.pb.h"

// MockControllerStub is a mock implementation of the Controller::StubInterface interface.
class MockControllerStub {
public:
    MOCK_METHOD3(Create, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::containerd::services::sandbox::v1::ControllerCreateResponse* response));
    MOCK_METHOD3(Start, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::containerd::services::sandbox::v1::ControllerStartResponse* response));
    MOCK_METHOD3(Platform, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::containerd::services::sandbox::v1::ControllerPlatformResponse* response));
    MOCK_METHOD3(Prepare, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::containerd::services::sandbox::v1::PrepareResponse* response));
    MOCK_METHOD3(Purge, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::containerd::services::sandbox::v1::PurgeResponse* response));
    MOCK_METHOD3(UpdateResources, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::containerd::services::sandbox::v1::UpdateResourcesResponse* response));
    MOCK_METHOD3(Stop, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::containerd::services::sandbox::v1::ControllerStopResponse* response));
    MOCK_METHOD3(Wait, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::containerd::services::sandbox::v1::ControllerWaitResponse* response));
    MOCK_METHOD3(Status, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::containerd::services::sandbox::v1::ControllerStatusResponse* response));
    MOCK_METHOD3(Shutdown, ::grpc::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::containerd::services::sandbox::v1::ControllerShutdownResponse* response));
    MOCK_METHOD3(AsyncCreateRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerCreateResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncCreateRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerCreateResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(AsyncStartRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStartResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncStartRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStartResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(AsyncPlatformRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerPlatformResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncPlatformRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerPlatformResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(AsyncPrepareRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PrepareResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncPrepareRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PrepareResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(AsyncPurgeRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PurgeResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncPurgeRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PurgeResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(AsyncUpdateResourcesRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::UpdateResourcesResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncUpdateResourcesRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::UpdateResourcesResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(AsyncStopRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStopResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncStopRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStopResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(AsyncWaitRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerWaitResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncWaitRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerWaitResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(AsyncStatusRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStatusResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncStatusRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStatusResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(AsyncShutdownRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerShutdownResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::grpc::CompletionQueue* cq));
    MOCK_METHOD3(PrepareAsyncShutdownRaw, ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerShutdownResponse>*(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::grpc::CompletionQueue* cq));
};

class DummyControllerStub: public containerd::services::sandbox::v1::Controller::StubInterface {
public:
    DummyControllerStub() = default;
    ~DummyControllerStub() = default;
    ::grpc::Status Create(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::containerd::services::sandbox::v1::ControllerCreateResponse* response) override;
    ::grpc::Status Start(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::containerd::services::sandbox::v1::ControllerStartResponse* response) override;
    ::grpc::Status Platform(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::containerd::services::sandbox::v1::ControllerPlatformResponse* response) override;
    ::grpc::Status Prepare(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::containerd::services::sandbox::v1::PrepareResponse* response) override;
    ::grpc::Status Purge(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::containerd::services::sandbox::v1::PurgeResponse* response) override;
    ::grpc::Status UpdateResources(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::containerd::services::sandbox::v1::UpdateResourcesResponse* response) override;
    ::grpc::Status Stop(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::containerd::services::sandbox::v1::ControllerStopResponse* response) override;
    ::grpc::Status Wait(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::containerd::services::sandbox::v1::ControllerWaitResponse* response) override;
    ::grpc::Status Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::containerd::services::sandbox::v1::ControllerStatusResponse* response) override;
    ::grpc::Status Shutdown(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::containerd::services::sandbox::v1::ControllerShutdownResponse* response) override;
private:
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerCreateResponse>* AsyncCreateRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerCreateResponse>* PrepareAsyncCreateRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStartResponse>* AsyncStartRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStartResponse>* PrepareAsyncStartRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerPlatformResponse>* AsyncPlatformRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerPlatformResponse>* PrepareAsyncPlatformRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PrepareResponse>* AsyncPrepareRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PrepareResponse>* PrepareAsyncPrepareRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PurgeResponse>* AsyncPurgeRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PurgeResponse>* PrepareAsyncPurgeRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::UpdateResourcesResponse>* AsyncUpdateResourcesRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::UpdateResourcesResponse>* PrepareAsyncUpdateResourcesRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStopResponse>* AsyncStopRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStopResponse>* PrepareAsyncStopRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerWaitResponse>* AsyncWaitRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerWaitResponse>* PrepareAsyncWaitRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStatusResponse>* AsyncStatusRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStatusResponse>* PrepareAsyncStatusRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerShutdownResponse>* AsyncShutdownRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerShutdownResponse>* PrepareAsyncShutdownRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::grpc::CompletionQueue* cq) override;
};

std::unique_ptr<DummyControllerStub> NewDummyControllerStub();

void MockControllerStub_SetMock(std::shared_ptr<MockControllerStub> stub);


#endif // _ISULAD_TEST_MOCKS_CONTROLLER_STUB_MOCK_H