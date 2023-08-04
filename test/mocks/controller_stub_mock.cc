#include "controller_stub_mock.h"

static std::shared_ptr<MockControllerStub> g_controller_stub_mock = NULL;

std::unique_ptr<DummyControllerStub> NewDummyControllerStub() {
  std::unique_ptr<DummyControllerStub> stub(new DummyControllerStub());
  return stub;
}

void MockControllerStub_SetMock(std::shared_ptr<MockControllerStub> mock) {
    g_controller_stub_mock = mock;
}

::grpc::Status DummyControllerStub::Create(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::containerd::services::sandbox::v1::ControllerCreateResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->Create(context, request, response);
}

::grpc::Status DummyControllerStub::Start(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::containerd::services::sandbox::v1::ControllerStartResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->Start(context, request, response);
}

::grpc::Status DummyControllerStub::Platform(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::containerd::services::sandbox::v1::ControllerPlatformResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->Platform(context, request, response);
}

::grpc::Status DummyControllerStub::Prepare(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::containerd::services::sandbox::v1::PrepareResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->Prepare(context, request, response);
}

::grpc::Status DummyControllerStub::Purge(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::containerd::services::sandbox::v1::PurgeResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->Purge(context, request, response);
}

::grpc::Status DummyControllerStub::UpdateResources(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::containerd::services::sandbox::v1::UpdateResourcesResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->UpdateResources(context, request, response);
}

::grpc::Status DummyControllerStub::Stop(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::containerd::services::sandbox::v1::ControllerStopResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->Stop(context, request, response);
}

::grpc::Status DummyControllerStub::Wait(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::containerd::services::sandbox::v1::ControllerWaitResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->Wait(context, request, response);
}

::grpc::Status DummyControllerStub::Status(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::containerd::services::sandbox::v1::ControllerStatusResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->Status(context, request, response);
}

::grpc::Status DummyControllerStub::Shutdown(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::containerd::services::sandbox::v1::ControllerShutdownResponse* response) {
  if (g_controller_stub_mock == NULL) {
    return ::grpc::Status::OK;
  }
  return g_controller_stub_mock->Shutdown(context, request, response);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerCreateResponse>* DummyControllerStub::AsyncCreateRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncCreateRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerCreateResponse>* DummyControllerStub::PrepareAsyncCreateRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerCreateRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncCreateRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStartResponse>* DummyControllerStub::AsyncStartRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncStartRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStartResponse>* DummyControllerStub::PrepareAsyncStartRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStartRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncStartRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerPlatformResponse>* DummyControllerStub::AsyncPlatformRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncPlatformRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerPlatformResponse>* DummyControllerStub::PrepareAsyncPlatformRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerPlatformRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncPlatformRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PrepareResponse>* DummyControllerStub::AsyncPrepareRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncPrepareRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PrepareResponse>* DummyControllerStub::PrepareAsyncPrepareRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PrepareRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncPrepareRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PurgeResponse>* DummyControllerStub::AsyncPurgeRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncPurgeRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::PurgeResponse>* DummyControllerStub::PrepareAsyncPurgeRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::PurgeRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncPurgeRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::UpdateResourcesResponse>* DummyControllerStub::AsyncUpdateResourcesRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncUpdateResourcesRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::UpdateResourcesResponse>* DummyControllerStub::PrepareAsyncUpdateResourcesRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::UpdateResourcesRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncUpdateResourcesRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStopResponse>* DummyControllerStub::AsyncStopRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncStopRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStopResponse>* DummyControllerStub::PrepareAsyncStopRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStopRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncStopRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerWaitResponse>* DummyControllerStub::AsyncWaitRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncWaitRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerWaitResponse>* DummyControllerStub::PrepareAsyncWaitRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerWaitRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncWaitRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStatusResponse>* DummyControllerStub::AsyncStatusRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncStatusRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerStatusResponse>* DummyControllerStub::PrepareAsyncStatusRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerStatusRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncStatusRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerShutdownResponse>* DummyControllerStub::AsyncShutdownRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->AsyncShutdownRaw(context, request, cq);
}

::grpc::ClientAsyncResponseReaderInterface< ::containerd::services::sandbox::v1::ControllerShutdownResponse>* DummyControllerStub::PrepareAsyncShutdownRaw(::grpc::ClientContext* context, const ::containerd::services::sandbox::v1::ControllerShutdownRequest& request, ::grpc::CompletionQueue* cq) {
  if (g_controller_stub_mock == NULL) {
    return NULL;
  }
  return g_controller_stub_mock->PrepareAsyncShutdownRaw(context, request, cq);
}
