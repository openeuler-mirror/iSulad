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
#include "mock.h"

extern "C" {
    DECLARE_WRAPPER(isula_common_calloc_s, void *, (size_t size));
    DEFINE_WRAPPER(isula_common_calloc_s, void *, (size_t size), (size));
}

class ShimControllerTest : public testing::Test {
protected:
    void SetUp() override
    {
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

    void TearDown() override
    {
        m_contoller.reset(nullptr);
        MockCallback_SetMock(nullptr);
        MockServiceContainerApi_SetMock(nullptr);
        MockImageApi_SetMock(nullptr);
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

TEST_F(ShimControllerTest, CreateTestContainerCallbackNullPtrError)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // shim controller create needs linux config.
    (void)params->config->mutable_linux();
    (void)params->config->mutable_linux()->mutable_resources();
    auto callback = get_service_executor();
    auto tmp_create = callback->container.create;
    callback->container.create = nullptr;
    EXPECT_FALSE(m_contoller->Create(DUMMY_SANDBOX_ID, *params, err));
    callback->container.create = tmp_create;
}

TEST_F(ShimControllerTest, CreateTestContainerCallocError)
{
    Errors err;
    std::unique_ptr<sandbox::ControllerCreateParams> params = CreateTestCreateParams();
    // shim controller create needs linux config.
    (void)params->config->mutable_linux();
    (void)params->config->mutable_linux()->mutable_resources();
    MOCK_SET(isula_common_calloc_s, nullptr);
    EXPECT_FALSE(m_contoller->Create(DUMMY_SANDBOX_ID, *params, err));
    MOCK_CLEAR(isula_common_calloc_s);
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

TEST_F(ShimControllerTest, StartTestFailed)
{
    Errors err;
    EXPECT_CALL(*m_containerCallbackMock, ContainerStart).Times(1).WillOnce(testing::Return(1));
    std::unique_ptr<sandbox::ControllerSandboxInfo> ret = m_contoller->Start(DUMMY_SANDBOX_ID, err);
    EXPECT_EQ(ret, nullptr);
}

TEST_F(ShimControllerTest, StartTestContainerCallbackNullPtrError)
{
    Errors err;
    auto callback = get_service_executor();
    auto tmp_start = callback->container.start;
    callback->container.start = nullptr;
    EXPECT_FALSE(m_contoller->Start(DUMMY_SANDBOX_ID, err));
    callback->container.start = tmp_start;
}

TEST_F(ShimControllerTest, StartTestContainerCallocError)
{
    Errors err;
    MOCK_SET(isula_common_calloc_s, nullptr);
    EXPECT_FALSE(m_contoller->Start(DUMMY_SANDBOX_ID, err));
    MOCK_CLEAR(isula_common_calloc_s);
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

TEST_F(ShimControllerTest, StopTestContainerCallbackNullPtrError)
{
    Errors err;
    auto callback = get_service_executor();
    auto tmp_stop = callback->container.stop;
    callback->container.stop = nullptr;
    EXPECT_FALSE(m_contoller->Stop(DUMMY_SANDBOX_ID, 0, err));
    callback->container.stop = tmp_stop;
}

TEST_F(ShimControllerTest, StopTestContainerCallocError)
{
    Errors err;
    MOCK_SET(isula_common_calloc_s, nullptr);
    EXPECT_FALSE(m_contoller->Stop(DUMMY_SANDBOX_ID, 0, err));
    MOCK_CLEAR(isula_common_calloc_s);
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

TEST_F(ShimControllerTest, ShutdownTestContainerCallbackNullPtrError)
{
    Errors err;
    auto callback = get_service_executor();
    auto tmp_remove = callback->container.remove;
    callback->container.remove = nullptr;
    EXPECT_FALSE(m_contoller->Shutdown(DUMMY_SANDBOX_ID, err));
    callback->container.remove = tmp_remove;
}

TEST_F(ShimControllerTest, ShutdownTestContainerCallocError)
{
    Errors err;
    MOCK_SET(isula_common_calloc_s, nullptr);
    EXPECT_FALSE(m_contoller->Shutdown(DUMMY_SANDBOX_ID, err));
    MOCK_CLEAR(isula_common_calloc_s);
}

/*********** Unit tests for Platform ***********/
TEST_F(ShimControllerTest, PlatformTestSucceed)
{
    Errors err;
    // Not support yet
    std::unique_ptr<sandbox::ControllerPlatformInfo> ret = m_contoller->Platform(DUMMY_SANDBOX_ID, err);
    EXPECT_EQ(ret, nullptr);
}

/*********** Unit tests for Update ***********/
TEST_F(ShimControllerTest, UpdateTestSucceed)
{
    Errors err;
    // Shim Controller update is always true
    EXPECT_TRUE(m_contoller->Update(nullptr, nullptr, err));
}

/*********** Unit tests for UpdateNetworkSettings ***********/
TEST_F(ShimControllerTest, UpdateNetworkSettingsTestCallbackNullPtrError)
{
    Errors err;
    auto callback = get_service_executor();
    auto tmp_update_network_settings = callback->container.update_network_settings;
    callback->container.update_network_settings = nullptr;
    EXPECT_FALSE(m_contoller->UpdateNetworkSettings(DUMMY_SANDBOX_ID, "networkSettings", err));
    callback->container.update_network_settings = tmp_update_network_settings;
}

TEST_F(ShimControllerTest, UpdateNetworkSettingsTestContainerCallocError)
{
    Errors err;
    MOCK_SET(isula_common_calloc_s, nullptr);
    EXPECT_FALSE(m_contoller->UpdateNetworkSettings(DUMMY_SANDBOX_ID, "networkSettings", err));
    MOCK_CLEAR(isula_common_calloc_s);
}
