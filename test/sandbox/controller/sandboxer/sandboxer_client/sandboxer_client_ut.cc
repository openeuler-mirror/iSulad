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
 * Description: Sandboxer client UT
 ******************************************************************************/

#include "gtest/gtest.h"
#include "controller_stub_mock.h"
#include "grpc_sandboxer_client.h"
#include "controller_common.h"
#include "controller.h"

class SandboxerClientWrapper : public sandbox::SandboxerClient {
public:
    SandboxerClientWrapper(const std::string &sandboxer, const std::string &address) : SandboxerClient(sandboxer, address) {
        m_stub = NewDummyControllerStub();
    }

    ~SandboxerClientWrapper() = default;
};

class ControllerSandboxerClientTest : public testing::Test {
protected:
    void SetUp() override {
        m_sandboxer = "sandboxer";
        m_address = "/tmp/sandboxer.sock";

        m_sandboxerClient = std::make_shared<SandboxerClientWrapper>(m_sandboxer, m_address);
        m_stub = std::make_shared<MockControllerStub>();
        MockControllerStub_SetMock(m_stub);
    }

    void TearDown() override {
        MockControllerStub_SetMock(nullptr);
    }

    std::string m_sandboxer;
    std::string m_address;

    std::shared_ptr<MockControllerStub> m_stub;
    std::shared_ptr<SandboxerClientWrapper> m_sandboxerClient;
};

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
TEST_F(ControllerSandboxerClientTest, CreateTestSucceed) {
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // Fake a grpc create response.
    containerd::services::sandbox::v1::ControllerCreateResponse response;
    response.set_sandbox_id(DUMMY_SANDBOX_ID);
    // Set response to return sandbox_id, and return OK for stub_->Create().
    EXPECT_CALL(*m_stub, Create).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(response), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, CreateTestNullConfig) {
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params(new sandbox::ControllerCreateParams());
    params->config = nullptr;
    // Stub should not be called
    EXPECT_CALL(*m_stub, Create).Times(0);
    EXPECT_FALSE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_FALSE(err.Empty());
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to init create request for sandboxer create request"));
}

TEST_F(ControllerSandboxerClientTest, CreateTestNullMount) {
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    params->mounts.push_back(nullptr);
    containerd::services::sandbox::v1::ControllerCreateRequest request;
    // Save request to check mount size.
    EXPECT_CALL(*m_stub, Create).Times(1).WillOnce(testing::DoAll(testing::SaveArg<1>(&request), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    // The nullptr pushed in params should not be counted.
    EXPECT_EQ(request.rootfs_size(), 1);
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, CreateTestStatusNotOK) {
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // Fake a grpc create response.
    containerd::services::sandbox::v1::ControllerCreateResponse response;
    response.set_sandbox_id(DUMMY_SANDBOX_ID);
    EXPECT_CALL(*m_stub, Create).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Start *************/
TEST_F(ControllerSandboxerClientTest, StartTestSucceed) {
    Errors err;
    sandbox::ControllerSandboxInfo sandboxInfo;
    std::unique_ptr<containerd::services::sandbox::v1::ControllerStartResponse> response = CreateTestGrpcStartResponse();
    EXPECT_CALL(*m_stub, Start).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*response), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Start(DUMMY_SANDBOX_ID, sandboxInfo, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(sandboxInfo.id, DUMMY_SANDBOX_ID);
    EXPECT_EQ(sandboxInfo.pid, 1);
    EXPECT_EQ(sandboxInfo.createdAt, DUMMY_CREATE_AT);
    EXPECT_EQ(sandboxInfo.labels.size(), 1);
    EXPECT_EQ(sandboxInfo.labels["label1"], "value1");
}

TEST_F(ControllerSandboxerClientTest, StartTestStatusNotOK) {
    Errors err;
    sandbox::ControllerSandboxInfo sandboxInfo;
    EXPECT_CALL(*m_stub, Start).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Start(DUMMY_SANDBOX_ID, sandboxInfo, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Prepare *************/
TEST_F(ControllerSandboxerClientTest, PrepareTestSucceed) {
    Errors err;
    std::string bundle;
    std::unique_ptr<sandbox::ControllerPrepareParams> params = CreateTestPrepareParams();
    // Fake a grpc prepare response.
    containerd::services::sandbox::v1::PrepareResponse response;
    response.set_bundle("/tmp/bundle");
    // Set response to return bundle, and return OK for stub_->Prepare().
    EXPECT_CALL(*m_stub, Prepare).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(response), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Prepare(DUMMY_SANDBOX_ID, *params, bundle, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(bundle, "/tmp/bundle");
}

TEST_F(ControllerSandboxerClientTest, PrepareTestNullSpec) {
    Errors err;
    std::string bundle;
    std::unique_ptr<sandbox::ControllerPrepareParams> params = CreateTestPrepareParams();
    params->spec = nullptr;
    // Stub should not be called
    EXPECT_CALL(*m_stub, Prepare).Times(0);
    EXPECT_FALSE(m_sandboxerClient->Prepare(DUMMY_SANDBOX_ID, *params, bundle, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to init prepare request for sandboxer prepare request"));
}

TEST_F(ControllerSandboxerClientTest, PrepareTestNullMount) {
    Errors err;
    std::string bundle;
    std::unique_ptr<sandbox::ControllerPrepareParams> params = CreateTestPrepareParams();
    params->rootfs.push_back(nullptr);
    containerd::services::sandbox::v1::PrepareRequest request;
    // Save request to check mount size.
    EXPECT_CALL(*m_stub, Prepare).Times(1).WillOnce(testing::DoAll(testing::SaveArg<1>(&request), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Prepare(DUMMY_SANDBOX_ID, *params, bundle, err));
    // The nullptr pushed in params should not be counted.
    EXPECT_EQ(request.rootfs_size(), 2);
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, PrepareTestStatusNotOK) {
    Errors err;
    std::string bundle;
    std::unique_ptr<sandbox::ControllerPrepareParams> params = CreateTestPrepareParams();
    EXPECT_CALL(*m_stub, Prepare).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Prepare(DUMMY_SANDBOX_ID, *params, bundle, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Purge *************/
TEST_F(ControllerSandboxerClientTest, PurgeTestSucceed) {
    Errors err;
    // Set response to return OK for stub_->Purge().
    EXPECT_CALL(*m_stub, Purge).Times(1).WillOnce(testing::Return(grpc::Status::OK));
    EXPECT_TRUE(m_sandboxerClient->Purge(DUMMY_SANDBOX_ID, DUMMY_CONTAINER_ID, DUMMY_EXEC_ID, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, PurgeTestStatusNotOK) {
    Errors err;
    EXPECT_CALL(*m_stub, Purge).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Purge(DUMMY_SANDBOX_ID, DUMMY_CONTAINER_ID, DUMMY_EXEC_ID, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for UpdateResources *************/
TEST_F(ControllerSandboxerClientTest, UpdateResourcesTestSucceed) {
    Errors err;
    google::protobuf::Map<std::string, std::string> annotations;
    std::unique_ptr<sandbox::ControllerUpdateResourcesParams> params = CreateTestUpdateResourcesParams(annotations);
    // Set response to return OK for stub_->UpdateResources().
    EXPECT_CALL(*m_stub, UpdateResources).Times(1).WillOnce(testing::Return(grpc::Status::OK));
    EXPECT_TRUE(m_sandboxerClient->UpdateResources(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, UpdateResourcesTestNullResources) {
    Errors err;
    google::protobuf::Map<std::string, std::string> annotations;
    std::unique_ptr<sandbox::ControllerUpdateResourcesParams> params = CreateTestUpdateResourcesParams(annotations);
    params->resources = nullptr;
    // Stub should not be called
    EXPECT_CALL(*m_stub, UpdateResources).Times(0);
    EXPECT_FALSE(m_sandboxerClient->UpdateResources(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to init update-resources request for sandboxer update-resources request"));
}

TEST_F(ControllerSandboxerClientTest, UpdateResourcesTestStatusNotOK) {
    Errors err;
    google::protobuf::Map<std::string, std::string> annotations;
    std::unique_ptr<sandbox::ControllerUpdateResourcesParams> params = CreateTestUpdateResourcesParams(annotations);
    EXPECT_CALL(*m_stub, UpdateResources).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->UpdateResources(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Platform *************/
TEST_F(ControllerSandboxerClientTest, PlatformTestSucceed) {
    Errors err;
    sandbox::ControllerPlatformInfo platformInfo;
    std::unique_ptr<containerd::services::sandbox::v1::ControllerPlatformResponse> response = CreateTestPlatformResponse();
    EXPECT_CALL(*m_stub, Platform).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*response), testing::Return(grpc::Status::OK)));
    EXPECT_TRUE(m_sandboxerClient->Platform(DUMMY_SANDBOX_ID, platformInfo, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(platformInfo.os, "linux");
    EXPECT_EQ(platformInfo.arch, "amd64");
    EXPECT_EQ(platformInfo.variant, "ubuntu");
}

TEST_F(ControllerSandboxerClientTest, PlatformTestStatusNotOK) {
    Errors err;
    sandbox::ControllerPlatformInfo platformInfo;
    EXPECT_CALL(*m_stub, Platform).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Platform(DUMMY_SANDBOX_ID, platformInfo, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Stop *************/
TEST_F(ControllerSandboxerClientTest, StopTestSucceed) {
    Errors err;
    // Set response to return OK for stub_->Stop().
    EXPECT_CALL(*m_stub, Stop).Times(1).WillOnce(testing::Return(grpc::Status::OK));
    EXPECT_TRUE(m_sandboxerClient->Stop(DUMMY_SANDBOX_ID, 0, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, StopTestStatusNotOK) {
    Errors err;
    EXPECT_CALL(*m_stub, Stop).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Stop(DUMMY_SANDBOX_ID, 0, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Status *************/
TEST_F(ControllerSandboxerClientTest, StatusTestSucceed) {
    Errors err;
    sandbox::ControllerSandboxStatus sandboxStatus;
    std::unique_ptr<containerd::services::sandbox::v1::ControllerStatusResponse> response = CreateTestStatusResponse();
    EXPECT_CALL(*m_stub, Status).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*response), testing::Return(grpc::Status::OK)));
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

TEST_F(ControllerSandboxerClientTest, StatusTestStatusNotOK) {
    Errors err;
    sandbox::ControllerSandboxStatus sandboxStatus;
    EXPECT_CALL(*m_stub, Status).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Status(DUMMY_SANDBOX_ID, false, sandboxStatus, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Shutdown *************/
TEST_F(ControllerSandboxerClientTest, ShutdownTestSucceed) {
    Errors err;
    // Set response to return OK for stub_->Shutdown().
    EXPECT_CALL(*m_stub, Shutdown).Times(1).WillOnce(testing::Return(grpc::Status::OK));
    EXPECT_TRUE(m_sandboxerClient->Shutdown(DUMMY_SANDBOX_ID, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, ShutdownTestStatusNotOK) {
    Errors err;
    EXPECT_CALL(*m_stub, Shutdown).Times(1).WillOnce(testing::Return(grpc::Status(grpc::StatusCode::ABORTED, "gRPC Abort")));
    EXPECT_FALSE(m_sandboxerClient->Shutdown(DUMMY_SANDBOX_ID, err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("gRPC Abort"));
}

/************* Unit tests for Wait *************/
// TEST_F(ControllerSandboxerClientTest, WaitTestSucceed) {
//     Errors err;

//     sandbox::ControllerSandboxStatus sandboxStatus;
//     std::unique_ptr<containerd::services::sandbox::v1::ControllerStatusResponse> response = CreateTestStatusResponse();
//     EXPECT_CALL(*m_stub, Status).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*response), testing::Return(grpc::Status::OK)));
//     EXPECT_TRUE(m_sandboxerClient->Wait(DUMMY_SANDBOX_ID, false, sandboxStatus, err));
// }
