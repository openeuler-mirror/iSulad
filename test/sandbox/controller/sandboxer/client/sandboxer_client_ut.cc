#include "gtest/gtest.h"
#include "controller_stub_mock.h"
#include "grpc_sandboxer_client.h"
#include "controller.h"

const std::string DUMMY_SANDBOX_ID = "604db93a33ec4c7787e4f369338f5887";
const std::string DUMMY_CONTAINER_ID = "504db93a32ec4c9789e4d369a38f3889";
const std::string DUMMY_EXEC_ID = "504db93a32ec4c9789e4d369a38f37765";
const uint64_t SECOND_TO_NANOS = 1000000000;
const uint64_t DUMMY_CREATE_AT = 1588 * SECOND_TO_NANOS + 1588;
const std::string DUMMY_TASK_ADDRESS = "vsock://18982:1";

class SandboxerClientWrapper : public sandbox::SandboxerClient {
public:
    SandboxerClientWrapper(const std::string &sandboxer, const std::string &address) : sandbox::SandboxerClient(sandboxer, address) {}

    void UpdateStub(std::unique_ptr<containerd::services::sandbox::v1::Controller::StubInterface> stub) {
        stub_ = std::move(stub);
    }

    containerd::services::sandbox::v1::Controller::StubInterface &GetStub() {
        return *stub_;
    }
};

class ControllerSandboxerTest : public testing::Test {
protected:
    void SetUp() override {
        m_sandboxer = "sandboxer";
        m_address = "/tmp/sandboxer.sock";
        m_sandboxerClient = std::move(std::unique_ptr<SandboxerClientWrapper>(new SandboxerClientWrapper(m_sandboxer, m_address)));
        // Create a mock stub.
        auto stub = std::unique_ptr<containerd::services::sandbox::v1::MockControllerStub>(
            new containerd::services::sandbox::v1::MockControllerStub()
        );
        // Update the stub in the sandboxer client.
        m_sandboxerClient->UpdateStub(std::move(stub));
    }

    containerd::services::sandbox::v1::MockControllerStub &GetStub() {
        return dynamic_cast<containerd::services::sandbox::v1::MockControllerStub &>(m_sandboxerClient->GetStub());
    }

    void TearDown() override {
        m_sandboxerClient.reset();
    }

    std::string m_sandboxer;
    std::string m_address;

    std::unique_ptr<SandboxerClientWrapper> m_sandboxerClient;
};

static std::unique_ptr<sandbox::ControllerMountInfo> CreateTestMountInfo() {
    std::unique_ptr<sandbox::ControllerMountInfo> mountInfo(new sandbox::ControllerMountInfo());
    mountInfo->source = "/rootfs";
    mountInfo->destination = "/rootfs";
    mountInfo->type = "bind";
    return mountInfo;
}

static std::unique_ptr<sandbox::ControllerCreateParams> CreateTestCreateParams() {
    std::unique_ptr<sandbox::ControllerCreateParams> params(new sandbox::ControllerCreateParams());
    params->config = std::make_shared<runtime::v1::PodSandboxConfig>();
    params->netNSPath = "/proc/1/ns/net";
    params->mounts.push_back(std::move(CreateTestMountInfo()));
    return params;
}

static std::unique_ptr<containerd::services::sandbox::v1::ControllerStartResponse> CreateTestGrpcStartResponse() {
    std::unique_ptr<containerd::services::sandbox::v1::ControllerStartResponse> response(new containerd::services::sandbox::v1::ControllerStartResponse());
    response->set_sandbox_id(DUMMY_SANDBOX_ID);
    response->set_pid(1);
    response->mutable_created_at()->set_seconds(DUMMY_CREATE_AT/SECOND_TO_NANOS);
    response->mutable_created_at()->set_nanos(DUMMY_CREATE_AT%SECOND_TO_NANOS);
    response->mutable_labels()->insert({"label1", "value1"});
    return response;
}

// Create platform response for test.
static std::unique_ptr<containerd::services::sandbox::v1::ControllerPlatformResponse> CreateTestPlatformResponse() {
    std::unique_ptr<containerd::services::sandbox::v1::ControllerPlatformResponse> response(
        new containerd::services::sandbox::v1::ControllerPlatformResponse()
    );
    response->mutable_platform()->set_os("linux");
    response->mutable_platform()->set_architecture("amd64");
    response->mutable_platform()->set_variant("ubuntu");
    return response;
}

static std::unique_ptr<sandbox::ControllerStreamInfo> CreateTestStreamInfo() {
    std::unique_ptr<sandbox::ControllerStreamInfo> streamInfo(new sandbox::ControllerStreamInfo());
    streamInfo->stdin = "/tmp/stdin";
    streamInfo->stdout = "/tmp/stdout";
    streamInfo->stderr = "/tmp/stderr";
    streamInfo->terminal = true;
    return streamInfo;
}

static std::unique_ptr<sandbox::ControllerPrepareParams> CreateTestPrepareParams() {
    std::unique_ptr<sandbox::ControllerPrepareParams> params(new sandbox::ControllerPrepareParams());
    params->containerId = DUMMY_CONTAINER_ID;
    params->execId = DUMMY_EXEC_ID;
    params->spec = std::unique_ptr<std::string>(new std::string("{spec: test}"));
    params->rootfs.push_back(std::move(CreateTestMountInfo()));
    params->rootfs.push_back(std::move(CreateTestMountInfo()));
    params->streamInfo = CreateTestStreamInfo();
    return params;
}

static std::unique_ptr<sandbox::ControllerUpdateResourcesParams> CreateTestUpdateResourcesParams(google::protobuf::Map<std::string, std::string> &annotations) {
    std::unique_ptr<std::string> resources(new std::string("{cpu: 12}"));
    std::unique_ptr<sandbox::ControllerUpdateResourcesParams> params(
        new sandbox::ControllerUpdateResourcesParams{DUMMY_SANDBOX_ID, std::move(resources), annotations}
    );
    return params;
}

// Create status response for test
static std::unique_ptr<containerd::services::sandbox::v1::ControllerStatusResponse> CreateTestStatusResponse() {
    std::unique_ptr<containerd::services::sandbox::v1::ControllerStatusResponse> response(
        new containerd::services::sandbox::v1::ControllerStatusResponse()
    );
    response->set_sandbox_id(DUMMY_SANDBOX_ID);
    response->set_state("running");
    response->set_pid(1);
    response->set_task_address(DUMMY_TASK_ADDRESS);
    response->mutable_created_at()->set_seconds(DUMMY_CREATE_AT/SECOND_TO_NANOS);
    response->mutable_created_at()->set_nanos(DUMMY_CREATE_AT%SECOND_TO_NANOS);
    response->mutable_exited_at()->set_seconds(DUMMY_CREATE_AT/SECOND_TO_NANOS);
    response->mutable_exited_at()->set_nanos(DUMMY_CREATE_AT%SECOND_TO_NANOS);
    response->mutable_info()->insert({"info1", "value1"});
    response->mutable_extra()->set_value("{extra: test}");
    return response;
}

/************* Unit tests for Create *************/
TEST_F(ControllerSandboxerTest, CreateTestSucceed) {
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // Fake a grpc create response.
    containerd::services::sandbox::v1::ControllerCreateResponse response;
    response.set_sandbox_id(DUMMY_SANDBOX_ID);
    // Set response to return sandbox_id, and return OK for stub_->Create().
    EXPECT_CALL(GetStub(), Create).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(response), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerTest, CreateTestNullConfig) {
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params(new sandbox::ControllerCreateParams());
    params->config = nullptr;
    // Stub should not be called
    EXPECT_CALL(GetStub(), Create).Times(0);
    EXPECT_FALSE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_FALSE(err.Empty());
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to init create request for sandboxer create request"));
}

TEST_F(ControllerSandboxerTest, CreateTestNullMount) {
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    params->mounts.push_back(nullptr);
    containerd::services::sandbox::v1::ControllerCreateRequest request;
    // Save request to check mount size.
    EXPECT_CALL(GetStub(), Create).Times(1).WillOnce(testing::DoAll(testing::SaveArg<1>(&request), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    // The nullptr pushed in params should not be counted.
    EXPECT_EQ(request.rootfs_size(), 1);
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerTest, CreateTestStatusNotOK) {
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // Fake a grpc create response.
    containerd::services::sandbox::v1::ControllerCreateResponse response;
    response.set_sandbox_id(DUMMY_SANDBOX_ID);
    EXPECT_CALL(GetStub(), Create).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Start *************/
TEST_F(ControllerSandboxerTest, StartTestSucceed) {
    Errors err;
    sandbox::ControllerSandboxInfo sandboxInfo;
    std::unique_ptr<containerd::services::sandbox::v1::ControllerStartResponse> response = CreateTestGrpcStartResponse();
    EXPECT_CALL(GetStub(), Start).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*response), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Start(DUMMY_SANDBOX_ID, sandboxInfo, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(sandboxInfo.id, DUMMY_SANDBOX_ID);
    EXPECT_EQ(sandboxInfo.pid, 1);
    EXPECT_EQ(sandboxInfo.createdAt, DUMMY_CREATE_AT);
    EXPECT_EQ(sandboxInfo.labels.size(), 1);
    EXPECT_EQ(sandboxInfo.labels["label1"], "value1");
}

TEST_F(ControllerSandboxerTest, StartTestStatusNotOK) {
    Errors err;
    sandbox::ControllerSandboxInfo sandboxInfo;
    EXPECT_CALL(GetStub(), Start).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Start(DUMMY_SANDBOX_ID, sandboxInfo, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Prepare *************/
TEST_F(ControllerSandboxerTest, PrepareTestSucceed) {
    Errors err;
    std::string bundle;
    std::unique_ptr<sandbox::ControllerPrepareParams> params = CreateTestPrepareParams();
    // Fake a grpc prepare response.
    containerd::services::sandbox::v1::PrepareResponse response;
    response.set_bundle("/tmp/bundle");
    // Set response to return bundle, and return OK for stub_->Prepare().
    EXPECT_CALL(GetStub(), Prepare).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(response), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Prepare(DUMMY_SANDBOX_ID, *params, bundle, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(bundle, "/tmp/bundle");
}

TEST_F(ControllerSandboxerTest, PrepareTestNullSpec) {
    Errors err;
    std::string bundle;
    std::unique_ptr<sandbox::ControllerPrepareParams> params = CreateTestPrepareParams();
    params->spec = nullptr;
    // Stub should not be called
    EXPECT_CALL(GetStub(), Prepare).Times(0);
    EXPECT_FALSE(m_sandboxerClient->Prepare(DUMMY_SANDBOX_ID, *params, bundle, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to init prepare request for sandboxer prepare request"));
}

TEST_F(ControllerSandboxerTest, PrepareTestNullMount) {
    Errors err;
    std::string bundle;
    std::unique_ptr<sandbox::ControllerPrepareParams> params = CreateTestPrepareParams();
    params->rootfs.push_back(nullptr);
    containerd::services::sandbox::v1::PrepareRequest request;
    // Save request to check mount size.
    EXPECT_CALL(GetStub(), Prepare).Times(1).WillOnce(testing::DoAll(testing::SaveArg<1>(&request), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Prepare(DUMMY_SANDBOX_ID, *params, bundle, err));
    // The nullptr pushed in params should not be counted.
    EXPECT_EQ(request.rootfs_size(), 2);
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerTest, PrepareTestStatusNotOK) {
    Errors err;
    std::string bundle;
    std::unique_ptr<sandbox::ControllerPrepareParams> params = CreateTestPrepareParams();
    EXPECT_CALL(GetStub(), Prepare).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Prepare(DUMMY_SANDBOX_ID, *params, bundle, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Purge *************/
TEST_F(ControllerSandboxerTest, PurgeTestSucceed) {
    Errors err;
    // Set response to return OK for stub_->Purge().
    EXPECT_CALL(GetStub(), Purge).Times(1).WillOnce(testing::Return(grpc::Status::OK));
    EXPECT_TRUE(m_sandboxerClient->Purge(DUMMY_SANDBOX_ID, DUMMY_CONTAINER_ID, DUMMY_EXEC_ID, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerTest, PurgeTestStatusNotOK) {
    Errors err;
    EXPECT_CALL(GetStub(), Purge).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Purge(DUMMY_SANDBOX_ID, DUMMY_CONTAINER_ID, DUMMY_EXEC_ID, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for UpdateResources *************/
TEST_F(ControllerSandboxerTest, UpdateResourcesTestSucceed) {
    Errors err;
    google::protobuf::Map<std::string, std::string> annotations;
    std::unique_ptr<sandbox::ControllerUpdateResourcesParams> params = CreateTestUpdateResourcesParams(annotations);
    // Set response to return OK for stub_->UpdateResources().
    EXPECT_CALL(GetStub(), UpdateResources).Times(1).WillOnce(testing::Return(grpc::Status::OK));
    EXPECT_TRUE(m_sandboxerClient->UpdateResources(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerTest, UpdateResourcesTestNullResources) {
    Errors err;
    google::protobuf::Map<std::string, std::string> annotations;
    std::unique_ptr<sandbox::ControllerUpdateResourcesParams> params = CreateTestUpdateResourcesParams(annotations);
    params->resources = nullptr;
    // Stub should not be called
    EXPECT_CALL(GetStub(), UpdateResources).Times(0);
    EXPECT_FALSE(m_sandboxerClient->UpdateResources(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to init update-resources request for sandboxer update-resources request"));
}

TEST_F(ControllerSandboxerTest, UpdateResourcesTestStatusNotOK) {
    Errors err;
    google::protobuf::Map<std::string, std::string> annotations;
    std::unique_ptr<sandbox::ControllerUpdateResourcesParams> params = CreateTestUpdateResourcesParams(annotations);
    EXPECT_CALL(GetStub(), UpdateResources).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->UpdateResources(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Platform *************/
TEST_F(ControllerSandboxerTest, PlatformTestSucceed) {
    Errors err;
    sandbox::ControllerPlatformInfo platformInfo;
    std::unique_ptr<containerd::services::sandbox::v1::ControllerPlatformResponse> response = CreateTestPlatformResponse();
    EXPECT_CALL(GetStub(), Platform).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*response), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Platform(DUMMY_SANDBOX_ID, platformInfo, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(platformInfo.os, "linux");
    EXPECT_EQ(platformInfo.arch, "amd64");
    EXPECT_EQ(platformInfo.variant, "ubuntu");
}

TEST_F(ControllerSandboxerTest, PlatformTestStatusNotOK) {
    Errors err;
    sandbox::ControllerPlatformInfo platformInfo;
    EXPECT_CALL(GetStub(), Platform).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Platform(DUMMY_SANDBOX_ID, platformInfo, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Stop *************/
TEST_F(ControllerSandboxerTest, StopTestSucceed) {
    Errors err;
    // Set response to return OK for stub_->Stop().
    EXPECT_CALL(GetStub(), Stop).Times(1).WillOnce(testing::Return(grpc::Status::OK));
    EXPECT_TRUE(m_sandboxerClient->Stop(DUMMY_SANDBOX_ID, 0, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerTest, StopTestStatusNotOK) {
    Errors err;
    EXPECT_CALL(GetStub(), Stop).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Stop(DUMMY_SANDBOX_ID, 0, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Status *************/
TEST_F(ControllerSandboxerTest, StatusTestSucceed) {
    Errors err;
    sandbox::ControllerSandboxStatus sandboxStatus;
    std::unique_ptr<containerd::services::sandbox::v1::ControllerStatusResponse> response = CreateTestStatusResponse();
    EXPECT_CALL(GetStub(), Status).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*response), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Status(DUMMY_SANDBOX_ID, false, sandboxStatus, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(sandboxStatus.id, DUMMY_SANDBOX_ID);
    EXPECT_EQ(sandboxStatus.state, "running");
    EXPECT_EQ(sandboxStatus.pid, 1);
    EXPECT_EQ(sandboxStatus.taskAddress, DUMMY_TASK_ADDRESS);
    EXPECT_EQ(sandboxStatus.createdAt, DUMMY_CREATE_AT);
    EXPECT_EQ(sandboxStatus.exitedAt, DUMMY_CREATE_AT);
    EXPECT_EQ(sandboxStatus.info.size(), 1);
    EXPECT_EQ(sandboxStatus.info["info1"], "value1");
    EXPECT_EQ(sandboxStatus.extra, "{extra: test}");
}

TEST_F(ControllerSandboxerTest, StatusTestStatusNotOK) {
    Errors err;
    sandbox::ControllerSandboxStatus sandboxStatus;
    EXPECT_CALL(GetStub(), Status).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Status(DUMMY_SANDBOX_ID, false, sandboxStatus, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Shutdown *************/
TEST_F(ControllerSandboxerTest, ShutdownTestSucceed) {
    Errors err;
    // Set response to return OK for stub_->Shutdown().
    EXPECT_CALL(GetStub(), Shutdown).Times(1).WillOnce(testing::Return(grpc::Status::OK));
    EXPECT_TRUE(m_sandboxerClient->Shutdown(DUMMY_SANDBOX_ID, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerTest, ShutdownTestStatusNotOK) {
    Errors err;
    EXPECT_CALL(GetStub(), Shutdown).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Shutdown(DUMMY_SANDBOX_ID, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}
