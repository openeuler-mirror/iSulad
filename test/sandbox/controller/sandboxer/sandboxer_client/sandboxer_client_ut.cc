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

#include <isula_libutils/json_common.h>

#include "gtest/gtest.h"
#include "grpc_sandboxer_client.h"
#include "grpc_sandboxer_client_mock.h"
#include "rust_sandbox_api_mock.h"
#include "sandbox_manager_mock.h"
#include "controller_common.h"
#include "controller.h"
#include "utils.h"

class ControllerSandboxerClientTest : public testing::Test {
protected:
    void SetUp() override
    {
        m_sandboxer = "sandboxer";
        m_address = "/tmp/sandboxer.sock";
        ControllerHandle_t handle_ptr = (ControllerHandle_t)(0x1); // just not nullptr

        m_sandboxManagerMock = std::make_shared<MockSandboxManager>();
        MockSandboxManager_SetMock(m_sandboxManagerMock);
        m_rustSandboxApiMock = std::make_shared<RustSandboxApiMock>();
        RustSandboxApiMock_SetMock(m_rustSandboxApiMock);

        EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_build_controller).Times(1).WillOnce(testing::DoAll(testing::Return(handle_ptr)));
        m_sandboxerClient = std::make_shared<SandboxerClient>(m_sandboxer, m_address);
    }

    void TearDown() override
    {
        MockSandboxManager_SetMock(nullptr);
        RustSandboxApiMock_SetMock(nullptr);
    }

    std::string m_sandboxer;
    std::string m_address;
    std::shared_ptr<SandboxerClient> m_sandboxerClient;
    std::shared_ptr<MockSandboxManager> m_sandboxManagerMock = nullptr;
    std::shared_ptr<RustSandboxApiMock> m_rustSandboxApiMock = nullptr;
};

/************* Unit tests for Create *************/
TEST_F(ControllerSandboxerClientTest, CreateTestSucceed)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();

    // Set response to return sandbox_id, and return OK for sandbox_api_create().
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_create).Times(1).WillOnce(testing::DoAll(testing::Return(0)));
    EXPECT_TRUE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, CreateTestNullConfig)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params(new sandbox::ControllerCreateParams());
    params->config = nullptr;
    // Stub should not be called
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_create).Times(0);
    EXPECT_FALSE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_FALSE(err.Empty());
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to init create request for sandboxer create request"));
}

TEST_F(ControllerSandboxerClientTest, CreateTestNullMount)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    params->mounts.push_back(nullptr);
    // Save request to check mount size.
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_create).Times(1).WillOnce(testing::DoAll(testing::Return(0)));
    EXPECT_TRUE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, CreateTestStatusNotOK)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();

    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_create).Times(1).WillOnce(testing::Return(-1));
    EXPECT_FALSE(m_sandboxerClient->Create(DUMMY_SANDBOX_ID, *params, err));
}

/************* Unit tests for Start *************/
static std::unique_ptr<CStructWrapper<json_map_string_string>> GetMockLabels()
{
    json_map_string_string *labels = nullptr;
    size_t len = 1;

    auto labels_wrapper = makeUniquePtrCStructWrapper<json_map_string_string>(free_json_map_string_string);
    if (labels_wrapper == nullptr) {
        return nullptr;
    }
    labels = labels_wrapper->get();

    labels->keys = (char **)util_smart_calloc_s(sizeof(char *), len);
    if (labels->keys == nullptr) {
        return nullptr;
    }
    labels->keys[0] = util_strdup_s("label1");
    labels->values = (char **)util_smart_calloc_s(sizeof(char *), len);
    if (labels->values == nullptr) {
        return nullptr;
    }
    labels->values[0] = util_strdup_s("value1");
    labels->len = len;

    return labels_wrapper;
}

static std::unique_ptr<CStructWrapper<sandbox_start_response>> GetMockSandboxStartResponse()
{
    sandbox_start_response *reponse = nullptr;

    auto reponse_wrapper = makeUniquePtrCStructWrapper<sandbox_start_response>(free_sandbox_start_response);
    if (reponse_wrapper == nullptr) {
        return nullptr;
    }
    reponse = reponse_wrapper->get();

    reponse->sandbox_id = util_strdup_s(DUMMY_SANDBOX_ID.c_str());
    reponse->pid = 1;
    reponse->created_at = DUMMY_CREATE_AT;
    reponse->address = util_strdup_s(DUMMY_TASK_ADDRESS.c_str());
    reponse->version = 0;
    reponse->labels = GetMockLabels()->move();

    return reponse_wrapper;
}

TEST_F(ControllerSandboxerClientTest, StartTestSucceed)
{
    Errors err;
    sandbox::ControllerSandboxInfo sandboxInfo;

    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_start).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*(GetMockSandboxStartResponse()->move())),
                                                                 testing::Return(0)));
    EXPECT_TRUE(m_sandboxerClient->Start(DUMMY_SANDBOX_ID, sandboxInfo, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(sandboxInfo.id, DUMMY_SANDBOX_ID);
    EXPECT_EQ(sandboxInfo.pid, 1);
    EXPECT_EQ(sandboxInfo.createdAt, DUMMY_CREATE_AT);
    EXPECT_EQ(sandboxInfo.labels.size(), 1);
    EXPECT_EQ(sandboxInfo.labels["label1"], "value1");
}

TEST_F(ControllerSandboxerClientTest, StartTestStatusNotOK)
{
    Errors err;
    sandbox::ControllerSandboxInfo sandboxInfo;
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_start).Times(1).WillOnce(testing::Return(-1));
    EXPECT_FALSE(m_sandboxerClient->Start(DUMMY_SANDBOX_ID, sandboxInfo, err));
}

/************* Unit tests for Update *************/
TEST_F(ControllerSandboxerClientTest, UpdateTestSucceed)
{
    Errors err;
    auto apiSandbox = CreateTestUpdateApiSandbox();
    auto fields = CreateTestFields();
    // Set response to return bundle, and return OK for sandbox_api_update().
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_update).Times(1).WillOnce(testing::DoAll(testing::Return(0)));
    EXPECT_TRUE(m_sandboxerClient->Update(apiSandbox->get(), fields->get(), err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, UpdateTestStatusNotOK)
{
    Errors err;
    auto apiSandbox = CreateTestUpdateApiSandbox();
    auto fields = CreateTestFields();
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_update).Times(1).WillOnce(testing::Return(-1));
    EXPECT_FALSE(m_sandboxerClient->Update(apiSandbox->get(), fields->get(), err));
}

/************* Unit tests for Platform *************/
static std::unique_ptr<CStructWrapper<sandbox_platform_response>> GetMockSandboxPlatformResponse()
{
    sandbox_platform_response *reponse = nullptr;

    auto reponse_wrapper = makeUniquePtrCStructWrapper<sandbox_platform_response>(free_sandbox_platform_response);
    if (reponse_wrapper == nullptr) {
        return nullptr;
    }
    reponse = reponse_wrapper->get();

    reponse->os = util_strdup_s("linux");
    reponse->architecture = util_strdup_s("amd64");
    reponse->variant = util_strdup_s("ubuntu");

    return reponse_wrapper;
}

TEST_F(ControllerSandboxerClientTest, PlatformTestSucceed)
{
    Errors err;
    sandbox::ControllerPlatformInfo platformInfo;
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_platform).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*(GetMockSandboxPlatformResponse()->move())),
                                                                    testing::Return(0)));
    EXPECT_TRUE(m_sandboxerClient->Platform(DUMMY_SANDBOX_ID, platformInfo, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(platformInfo.os, "linux");
    EXPECT_EQ(platformInfo.arch, "amd64");
    EXPECT_EQ(platformInfo.variant, "ubuntu");
}

TEST_F(ControllerSandboxerClientTest, PlatformTestStatusNotOK)
{
    Errors err;
    sandbox::ControllerPlatformInfo platformInfo;
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_platform).Times(1).WillOnce(testing::Return(-1));
    EXPECT_FALSE(m_sandboxerClient->Platform(DUMMY_SANDBOX_ID, platformInfo, err));
}

/************* Unit tests for Stop *************/
TEST_F(ControllerSandboxerClientTest, StopTestSucceed)
{
    Errors err;
    // Set response to return OK for sandbox_api_stop().
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_stop).Times(1).WillOnce(testing::Return(0));
    EXPECT_TRUE(m_sandboxerClient->Stop(DUMMY_SANDBOX_ID, 0, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, StopTestStatusNotOK)
{
    Errors err;
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_stop).Times(1).WillOnce(testing::Return(-1));
    EXPECT_FALSE(m_sandboxerClient->Stop(DUMMY_SANDBOX_ID, 0, err));
}

/************* Unit tests for Status *************/
static std::unique_ptr<CStructWrapper<sandbox_status_response>> GetMockSandboxStatusResponse()
{
    sandbox_status_response *reponse = nullptr;

    auto reponse_wrapper = makeUniquePtrCStructWrapper<sandbox_status_response>(free_sandbox_status_response);
    if (reponse_wrapper == nullptr) {
        return nullptr;
    }
    reponse = reponse_wrapper->get();

    reponse->sandbox_id = util_strdup_s(DUMMY_SANDBOX_ID.c_str());
    reponse->pid = 1;
    reponse->state = util_strdup_s("running");
    reponse->info = GetMockLabels()->move();
    if (reponse->info == nullptr) {
        return nullptr;
    }
    reponse->created_at = DUMMY_CREATE_AT;
    reponse->exited_at = DUMMY_CREATE_AT;
    reponse->extra = (defs_any *)util_common_calloc_s(sizeof(defs_any));
    if (reponse->extra == nullptr) {
        return nullptr;
    }
    reponse->extra->value = (uint8_t*)util_strdup_s("{extra: test}");
    reponse->extra->value_len = 13;
    reponse->address = util_strdup_s(DUMMY_TASK_ADDRESS.c_str());
    reponse->version = 0;

    return reponse_wrapper;
}

TEST_F(ControllerSandboxerClientTest, StatusTestSucceed)
{
    Errors err;
    sandbox::ControllerSandboxStatus sandboxStatus;

    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_status).Times(1).WillOnce(testing::DoAll(testing::SetArgPointee<2>(*(GetMockSandboxStatusResponse()->move())),
                                                                  testing::Return(0)));
    EXPECT_TRUE(m_sandboxerClient->Status(DUMMY_SANDBOX_ID, false, sandboxStatus, err));
    EXPECT_TRUE(err.Empty());
    EXPECT_EQ(sandboxStatus.id, DUMMY_SANDBOX_ID);
    EXPECT_EQ(sandboxStatus.state, "running");
    EXPECT_EQ(sandboxStatus.pid, 1);
    EXPECT_EQ(sandboxStatus.taskAddress, DUMMY_TASK_ADDRESS);
    EXPECT_EQ(sandboxStatus.createdAt, DUMMY_CREATE_AT);
    EXPECT_EQ(sandboxStatus.exitedAt, DUMMY_CREATE_AT);
    EXPECT_EQ(sandboxStatus.info.size(), 1);
    EXPECT_EQ(sandboxStatus.info["label1"], "value1");
    EXPECT_EQ(sandboxStatus.extra, "{extra: test}");
}

TEST_F(ControllerSandboxerClientTest, StatusTestStatusNotOK)
{
    Errors err;
    sandbox::ControllerSandboxStatus sandboxStatus;
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_status).Times(1).WillOnce(testing::Return(-1));
    EXPECT_FALSE(m_sandboxerClient->Status(DUMMY_SANDBOX_ID, false, sandboxStatus, err));
}

/************* Unit tests for Shutdown *************/
TEST_F(ControllerSandboxerClientTest, ShutdownTestSucceed)
{
    Errors err;
    // Set response to return OK for sandbox_api_shutdown().
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_shutdown).Times(1).WillOnce(testing::Return(0));
    EXPECT_TRUE(m_sandboxerClient->Shutdown(DUMMY_SANDBOX_ID, err));
    EXPECT_TRUE(err.Empty());
}

TEST_F(ControllerSandboxerClientTest, ShutdownTestStatusNotOK)
{
    Errors err;
    EXPECT_CALL(*m_rustSandboxApiMock, sandbox_api_shutdown).Times(1).WillOnce(testing::Return(-1));
    EXPECT_FALSE(m_sandboxerClient->Shutdown(DUMMY_SANDBOX_ID, err));
}
