#include "controller_stub_mock.h"

namespace containerd {
namespace services {
namespace sandbox {
namespace v1 {

std::unique_ptr<MockControllerStub> NewMockControllerStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  std::unique_ptr<MockControllerStub> stub(new MockControllerStub());
  return stub;
}

/* Rewrite all the functions for Controller::Stub with trival implementation */
::grpc::Status Controller::Stub::Create(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::containerd::services::sandbox::v1::ControllerCreateResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status Controller::Stub::Start(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::containerd::services::sandbox::v1::ControllerStartResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status Controller::Stub::Platform(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::containerd::services::sandbox::v1::ControllerPlatformResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status Controller::Stub::Prepare(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::containerd::services::sandbox::v1::PrepareResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status Controller::Stub::Purge(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::containerd::services::sandbox::v1::PurgeResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status Controller::Stub::UpdateResources(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::containerd::services::sandbox::v1::UpdateResourcesResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status Controller::Stub::Stop(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::containerd::services::sandbox::v1::ControllerStopResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status Controller::Stub::Wait(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::containerd::services::sandbox::v1::ControllerWaitResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status Controller::Stub::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::containerd::services::sandbox::v1::ControllerStatusResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::Status Controller::Stub::Shutdown(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::containerd::services::sandbox::v1::ControllerShutdownResponse* response) {
  return ::grpc::Status::OK;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerCreateResponse>* Controller::Stub::AsyncCreateRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerCreateResponse>* Controller::Stub::PrepareAsyncCreateRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerStartResponse>* Controller::Stub::AsyncStartRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}
::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerStartResponse>* Controller::Stub::PrepareAsyncStartRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerPlatformResponse>* Controller::Stub::AsyncPlatformRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerPlatformResponse>* Controller::Stub::PrepareAsyncPlatformRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::PrepareResponse>* Controller::Stub::AsyncPrepareRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::PrepareResponse>* Controller::Stub::PrepareAsyncPrepareRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::PurgeResponse>* Controller::Stub::AsyncPurgeRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::PurgeResponse>* Controller::Stub::PrepareAsyncPurgeRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::UpdateResourcesResponse>* Controller::Stub::AsyncUpdateResourcesRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::UpdateResourcesResponse>* Controller::Stub::PrepareAsyncUpdateResourcesRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerStopResponse>* Controller::Stub::AsyncStopRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerStopResponse>* Controller::Stub::PrepareAsyncStopRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerWaitResponse>* Controller::Stub::AsyncWaitRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerWaitResponse>* Controller::Stub::PrepareAsyncWaitRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerStatusResponse>* Controller::Stub::AsyncStatusRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerStatusResponse>* Controller::Stub::PrepareAsyncStatusRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerShutdownResponse>* Controller::Stub::AsyncShutdownRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

::grpc::ClientAsyncResponseReader< ::containerd::services::sandbox::v1::ControllerShutdownResponse>* Controller::Stub::PrepareAsyncShutdownRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::grpc::CompletionQueue* cq) {
  return nullptr;
}

// Return null_ptr for the original NewStub function, so that we can use the mock stub.
std::unique_ptr<Controller::Stub> Controller::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  return nullptr;
}

} // namespace v1
} // namespace sandbox
} // namespace services
} // namespace containerd