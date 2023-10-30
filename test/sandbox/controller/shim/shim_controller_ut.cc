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
 * Author: jikai
 * Create: 2023-10-20
 * Description: Shim controller UT
 ******************************************************************************/

#include <memory>
#include <gtest/gtest.h>

#include "callback_mock.h"
#include "controller_common.h"
#include "image_api_mock.h"
#include "service_container_api_mock.h"
#include "shim_controller.h"

class ShimControllerTest : public testing::Test {
protected:
    void SetUp() override {
        Errors err;
        m_contoller = std::move(std::unique_ptr<sandbox::ShimController>(new sandbox::ShimController(m_sandboxer)));
        m_containerCallbackMock = std::make_shared<MockContainerCallback>();
        m_serviceContainerApiMock = std::make_shared<MockServiceContainerApi>();
        m_imageApiMock = std::make_shared<MockImageApi>();
        MockCallback_SetMock(m_containerCallbackMock);
        MockServiceContainerApi_SetMock(m_serviceContainerApiMock);
        MockImageApi_SetMock(m_imageApiMock);
        m_contoller->Init(err);
        service_callback_init();
    }

    void TearDown() override {
        m_contoller.reset(nullptr);
    }

    std::string m_sandboxer = "shim";
    std::unique_ptr<sandbox::ShimController> m_contoller;
    std::shared_ptr<MockContainerCallback> m_containerCallbackMock = nullptr;
    std::shared_ptr<MockServiceContainerApi> m_serviceContainerApiMock = nullptr;
    std::shared_ptr<MockImageApi> m_imageApiMock = nullptr;
};

/************* Unit tests for Create *************/
TEST_F(ShimControllerTest, CreateTestSucceed)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // shim controller create needs linux config.
    (void)params->config->mutable_linux();
    (void)params->config->mutable_linux()->mutable_resources();
    EXPECT_CALL(*m_containerCallbackMock, ContainerCreate).Times(1).WillOnce(testing::Return(0));
    EXPECT_TRUE(m_contoller->Create(DUMMY_SANDBOX_ID, *params, err));
}

TEST_F(ShimControllerTest, CreateTestFailed)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // shim controller create needs linux config.
    (void)params->config->mutable_linux();
    (void)params->config->mutable_linux()->mutable_resources();
    EXPECT_CALL(*m_containerCallbackMock, ContainerCreate).Times(1).WillOnce(testing::Return(1));
    EXPECT_FALSE(m_contoller->Create(DUMMY_SANDBOX_ID, *params, err));
}

/************* Unit tests for Start *************/
TEST_F(ShimControllerTest, StartTestSucceed)
{
    Errors err;
    container_inspect *inspect = static_cast<container_inspect *>(util_common_calloc_s(sizeof(container_inspect)));
    if (inspect == nullptr) {
        ERROR("Out of memory");
        return;
    }
    inspect->id = util_strdup_s(DUMMY_SANDBOX_ID.c_str());
    inspect->state = static_cast<container_inspect_state *>(util_common_calloc_s(sizeof(container_inspect_state)));
    if (inspect->state == nullptr) {
        ERROR("Out of memory");
        return;
    }
    inspect->state->pid = 1234;
    EXPECT_CALL(*m_containerCallbackMock, ContainerStart).Times(1).WillOnce(testing::Return(0));
    EXPECT_CALL(*m_serviceContainerApiMock, InspectContainer).Times(1).WillOnce(testing::Return(inspect));
    std::unique_ptr<sandbox::ControllerSandboxInfo> ret = m_contoller->Start(DUMMY_SANDBOX_ID, err);
    EXPECT_EQ(ret->id, DUMMY_SANDBOX_ID);
    EXPECT_EQ(ret->pid, 1234);
}

/************* Unit tests for Start *************/
TEST_F(ShimControllerTest, StartTestFailed)
{
    Errors err;
    EXPECT_CALL(*m_containerCallbackMock, ContainerStart).Times(1).WillOnce(testing::Return(1));
    std::unique_ptr<sandbox::ControllerSandboxInfo> ret = m_contoller->Start(DUMMY_SANDBOX_ID, err);
    EXPECT_EQ(ret, nullptr);
}

/************* Unit tests for Stop *************/
TEST_F(ShimControllerTest, StopTestSucceed)
{
    Errors err;
    EXPECT_CALL(*m_containerCallbackMock, ContainerStop).Times(1).WillOnce(testing::Return(0));
    EXPECT_TRUE(m_contoller->Stop(DUMMY_SANDBOX_ID, 0, err));
}

TEST_F(ShimControllerTest, StopTestFailed)
{
    Errors err;
    EXPECT_CALL(*m_containerCallbackMock, ContainerStop).Times(1).WillOnce(testing::Return(1));
    EXPECT_FALSE(m_contoller->Stop(DUMMY_SANDBOX_ID, 0, err));
}

/************* Unit tests for Status *************/
TEST_F(ShimControllerTest, StatusTestSucceed)
{
    Errors err;
    container_inspect *inspect = static_cast<container_inspect *>(util_common_calloc_s(sizeof(container_inspect)));
    if (inspect == nullptr) {
        ERROR("Out of memory");
        return;
    }
    inspect->id = util_strdup_s(DUMMY_SANDBOX_ID.c_str());
    inspect->state = static_cast<container_inspect_state *>(util_common_calloc_s(sizeof(container_inspect_state)));
    if (inspect->state == nullptr) {
        ERROR("Out of memory");
        return;
    }
    inspect->state->pid = 1234;
    EXPECT_CALL(*m_serviceContainerApiMock, InspectContainer).Times(1).WillOnce(testing::Return(inspect));
    std::unique_ptr<sandbox::ControllerSandboxStatus> ret = m_contoller->Status(DUMMY_SANDBOX_ID, false, err);
    EXPECT_EQ(ret->id, DUMMY_SANDBOX_ID);
    EXPECT_EQ(ret->pid, 1234);
}

TEST_F(ShimControllerTest, StatusTestFailed)
{
    Errors err;
    EXPECT_CALL(*m_serviceContainerApiMock, InspectContainer).Times(1).WillOnce(testing::Return(nullptr));
    std::unique_ptr<sandbox::ControllerSandboxStatus> ret = m_contoller->Status(DUMMY_SANDBOX_ID, false, err);
    EXPECT_EQ(ret, nullptr);
}

/************* Unit tests for Shutdown *************/
TEST_F(ShimControllerTest, ShutdownTestSucceed)
{
    Errors err;
    EXPECT_CALL(*m_containerCallbackMock, ContainerRemove).Times(1).WillOnce(testing::Return(0));
    EXPECT_TRUE(m_contoller->Shutdown(DUMMY_SANDBOX_ID, err));
}

TEST_F(ShimControllerTest, ShutdownTestFailed)
{
    Errors err;
    EXPECT_CALL(*m_containerCallbackMock, ContainerRemove).Times(1).WillOnce(testing::Return(1));
    EXPECT_FALSE(m_contoller->Shutdown(DUMMY_SANDBOX_ID, err));
}
