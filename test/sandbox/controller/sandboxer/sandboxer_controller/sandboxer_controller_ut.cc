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
 * Description: Sandboxer controller UT
 ******************************************************************************/

#include <memory>
#include "gtest/gtest.h"
#include "sandboxer_controller.h"
#include "grpc_sandboxer_client_mock.h"
#include "controller_common.h"

class SandboxerControllerTest : public testing::Test {
protected:
    void SetUp() override
    {
        Errors err;
        m_contoller = std::move(std::unique_ptr<SandboxerController>(new SandboxerController(m_sandboxer, m_address)));
        m_sandboxerClientMock = std::make_shared<SandboxerClientMock>();
        MockSandboxerClient_SetMock(m_sandboxerClientMock);
    }

    void TearDown() override
    {
        m_contoller.reset(nullptr);
        MockSandboxerClient_SetMock(nullptr);
    }

    std::string m_sandboxer = "sandboxer";
    std::string m_address = "/tmp/sandboxer.sock";
    std::unique_ptr<SandboxerController> m_contoller;
    std::shared_ptr<SandboxerClientMock> m_sandboxerClientMock = nullptr;
};

static std::unique_ptr<sandbox::ControllerSandboxInfo> CreateTestSandboxInfo()
{
    std::unique_ptr<sandbox::ControllerSandboxInfo> sandboxInfo(new sandbox::ControllerSandboxInfo());
    sandboxInfo->id = DUMMY_SANDBOX_ID;
    sandboxInfo->pid = 1234;
    sandboxInfo->createdAt = DUMMY_CREATE_AT;
    return sandboxInfo;
}

/************* Unit tests for Create *************/
TEST_F(SandboxerControllerTest, CreateTestSucceed)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // Set response to return sandbox_id, and return OK for stub_->Create().
    EXPECT_CALL(*m_sandboxerClientMock, Create).Times(1).WillOnce(testing::Return(true));
    EXPECT_TRUE(m_contoller->Create(DUMMY_SANDBOX_ID, *params, err));
}

TEST_F(SandboxerControllerTest, CreateTestFailed)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // Set response to return sandbox_id, and return OK for stub_->Create().
    EXPECT_CALL(*m_sandboxerClientMock, Create).Times(1).WillOnce(testing::Return(false));
    EXPECT_FALSE(m_contoller->Create(DUMMY_SANDBOX_ID, *params, err));
}

/************* Unit tests for Start *************/
TEST_F(SandboxerControllerTest, StartTestSucceed)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerSandboxInfo> sandboxInfo = CreateTestSandboxInfo();
    // Set response to return sandbox_id, and return OK for stub_->Start().
    EXPECT_CALL(*m_sandboxerClientMock, Start).Times(1).WillOnce(testing::DoAll(testing::SetArgReferee<1>(*sandboxInfo),
                                                                                testing::Return(true)));
    std::unique_ptr<sandbox::ControllerSandboxInfo> ret = m_contoller->Start(DUMMY_SANDBOX_ID, err);
    EXPECT_EQ(ret->id, DUMMY_SANDBOX_ID);
    EXPECT_EQ(ret->pid, 1234);
    EXPECT_EQ(ret->createdAt, DUMMY_CREATE_AT);
}

TEST_F(SandboxerControllerTest, StartTestFailed)
{
    Errors err;
    // Set response to return sandbox_id, and return OK for stub_->Start().
    EXPECT_CALL(*m_sandboxerClientMock, Start).Times(1).WillOnce(testing::Return(false));
    std::unique_ptr<sandbox::ControllerSandboxInfo> ret = m_contoller->Start(DUMMY_SANDBOX_ID, err);
    EXPECT_EQ(ret, nullptr);
}

/************* Unit tests for Platform *************/
TEST_F(SandboxerControllerTest, PlatformTestSucceed)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerPlatformInfo> platformInfo(new sandbox::ControllerPlatformInfo());
    platformInfo->os = "linux";
    platformInfo->arch = "amd64";
    platformInfo->variant = "openEuler";
    // Set response to return sandbox_id, and return OK for stub_->Platform().
    EXPECT_CALL(*m_sandboxerClientMock, Platform).Times(1).WillOnce(testing::DoAll(testing::SetArgReferee<1>(*platformInfo),
                                                                                   testing::Return(true)));
    std::unique_ptr<sandbox::ControllerPlatformInfo> ret = m_contoller->Platform(DUMMY_SANDBOX_ID, err);
    EXPECT_EQ(ret->os, "linux");
    EXPECT_EQ(ret->arch, "amd64");
    EXPECT_EQ(ret->variant, "openEuler");
}

TEST_F(SandboxerControllerTest, PlatformTestFailed)
{
    Errors err;
    // Set response to return sandbox_id, and return OK for stub_->Platform().
    EXPECT_CALL(*m_sandboxerClientMock, Platform).Times(1).WillOnce(testing::Return(false));
    std::unique_ptr<sandbox::ControllerPlatformInfo> ret = m_contoller->Platform(DUMMY_SANDBOX_ID, err);
    EXPECT_EQ(ret, nullptr);
}

/************* Unit tests for Update *************/
TEST_F(SandboxerControllerTest, UpdateTestSucceed)
{
    Errors err;
    auto apiSandbox = CreateTestUpdateApiSandbox();
    auto fields = CreateTestFields();

    // return OK for stub_->Update().
    EXPECT_CALL(*m_sandboxerClientMock, Update).Times(1).WillOnce(testing::DoAll(testing::Return(true)));
    EXPECT_TRUE(m_contoller->Update(apiSandbox->get(), fields->get(), err));
}

TEST_F(SandboxerControllerTest, UpdateTestFailed)
{
    Errors err;
    auto apiSandbox = CreateTestUpdateApiSandbox();
    auto fields = CreateTestFields();

    // return OK for stub_->Update().
    EXPECT_CALL(*m_sandboxerClientMock, Update).Times(1).WillOnce(testing::Return(false));
    EXPECT_FALSE(m_contoller->Update(apiSandbox->get(), fields->get(), err)); 
}

/************* Unit tests for Stop *************/
TEST_F(SandboxerControllerTest, StopTestSucceed)
{
    Errors err;
    // Set response to return sandbox_id, and return OK for stub_->Stop().
    EXPECT_CALL(*m_sandboxerClientMock, Stop).Times(1).WillOnce(testing::Return(true));
    EXPECT_TRUE(m_contoller->Stop(DUMMY_SANDBOX_ID, 0, err));
}

TEST_F(SandboxerControllerTest, StopTestFailed)
{
    Errors err;
    // Set response to return sandbox_id, and return OK for stub_->Stop().
    EXPECT_CALL(*m_sandboxerClientMock, Stop).Times(1).WillOnce(testing::Return(false));
    EXPECT_FALSE(m_contoller->Stop(DUMMY_SANDBOX_ID, 0, err));
}

/************* Unit tests for Status *************/
TEST_F(SandboxerControllerTest, StatusTestSucceed)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerSandboxStatus> sandboxStatus(new sandbox::ControllerSandboxStatus());
    sandboxStatus->id = DUMMY_SANDBOX_ID;
    sandboxStatus->state = "created";
    sandboxStatus->pid = 1234;
    sandboxStatus->createdAt = DUMMY_CREATE_AT;
    sandboxStatus->taskAddress = DUMMY_TASK_ADDRESS;
    sandboxStatus->info["test"] = "test";
    sandboxStatus->exitedAt = DUMMY_EXITED_AT;
    // Set response to return sandbox_id, and return OK for stub_->Status().
    EXPECT_CALL(*m_sandboxerClientMock, Status).Times(1).WillOnce(testing::DoAll(testing::SetArgReferee<2>(*sandboxStatus),
                                                                                 testing::Return(true)));
    std::unique_ptr<sandbox::ControllerSandboxStatus> ret = m_contoller->Status(DUMMY_SANDBOX_ID, false, err);
    EXPECT_EQ(ret->id, DUMMY_SANDBOX_ID);
    EXPECT_EQ(ret->state, "created");
    EXPECT_EQ(ret->pid, 1234);
    EXPECT_EQ(ret->createdAt, DUMMY_CREATE_AT);
    EXPECT_EQ(ret->taskAddress, DUMMY_TASK_ADDRESS);
    EXPECT_EQ(ret->info["test"], "test");
    EXPECT_EQ(ret->exitedAt, DUMMY_EXITED_AT);
}

TEST_F(SandboxerControllerTest, StatusTestFailed)
{
    Errors err;
    // Set response to return sandbox_id, and return OK for stub_->Status().
    EXPECT_CALL(*m_sandboxerClientMock, Status).Times(1).WillOnce(testing::Return(false));
    std::unique_ptr<sandbox::ControllerSandboxStatus> ret = m_contoller->Status(DUMMY_SANDBOX_ID, false, err);
    EXPECT_EQ(ret, nullptr);
}

/************* Unit tests for Shutdown *************/
TEST_F(SandboxerControllerTest, ShutdownTestSucceed)
{
    Errors err;
    // Set response to return sandbox_id, and return OK for stub_->Shutdown().
    EXPECT_CALL(*m_sandboxerClientMock, Shutdown).Times(1).WillOnce(testing::Return(true));
    EXPECT_TRUE(m_contoller->Shutdown(DUMMY_SANDBOX_ID, err));
}

TEST_F(SandboxerControllerTest, ShutdownTestFailed)
{
    Errors err;
    // Set response to return sandbox_id, and return OK for stub_->Shutdown().
    EXPECT_CALL(*m_sandboxerClientMock, Shutdown).Times(1).WillOnce(testing::Return(false));
    EXPECT_FALSE(m_contoller->Shutdown(DUMMY_SANDBOX_ID, err));
}
