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

namespace containerd {
namespace services {
namespace sandbox {
namespace v1 {

// MockControllerStub is a mock implementation of the Controller::StubInterface interface.
class MockControllerStub final : public Controller::StubInterface {
public:
    MockControllerStub() = default;
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
private:
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

std::unique_ptr<MockControllerStub> NewMockControllerStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options);

} // namespace v1
} // namespace sandbox
} // namespace services
} // namespace containerd

#endif // _ISULAD_TEST_MOCKS_CONTROLLER_STUB_MOCK_H