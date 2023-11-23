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
 * Description: Controller manager UT
 ******************************************************************************/

#include <memory>
#include "gtest/gtest.h"
#include "sandboxer_controller.h"
#include "grpc_sandboxer_client_mock.h"
#include "controller_manager.h"
#include "controller_common.h"
#include "utils.h"
#include "isulad_config_mock.h"
#include "shim_controller.h"

class ControllerManagerWrapper : public sandbox::ControllerManager {
public:
    void Clear()
    {
        m_controllers.clear();
    }
};

class ControllerManagerTest : public testing::Test {
protected:
    void SetUp() override
    {
        MockIsuladConf_SetMock(isuladConfMock.get());
    }

    void TearDown() override
    {
        MockIsuladConf_SetMock(nullptr);
        static_cast<ControllerManagerWrapper*>(ControllerManagerWrapper::GetInstance())->Clear();
    }

    std::unique_ptr<MockIsuladConf> isuladConfMock = std::unique_ptr<MockIsuladConf>(new MockIsuladConf());
};

static struct service_arguments *CreateDummyServerConf(const std::string &conf)
{
    parser_error err = nullptr;
    struct service_arguments *args = (struct service_arguments *)util_common_calloc_s(sizeof(struct service_arguments));
    if (args == nullptr) {
        return nullptr;
    }
    args->json_confs = isulad_daemon_configs_parse_data(conf.c_str(), nullptr, &err);
    if (args->json_confs == nullptr) {
        free(args);
        return nullptr;
    }
    return args;
}

static void FreeDummyServerconf(struct service_arguments *args)
{
    if (args != nullptr) {
        free_isulad_daemon_configs(args->json_confs);
        free(args);
    }
}

/********* Init with valid sandboxers config **********/
TEST_F(ControllerManagerTest, InitTestSucceed)
{
    Errors err;
    const std::string daemonConfig =
        "{\"cri-sandboxers\": {\"kuasar\": {\"name\": \"vmm\",\"address\": \"/run/vmm-sandboxer.sock\"}}}";
    struct service_arguments *args = CreateDummyServerConf(daemonConfig);
    ASSERT_NE(args, nullptr);
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(1).WillOnce(testing::Return(args));
    EXPECT_TRUE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_TRUE(err.Empty());
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController(SHIM_CONTROLLER_NAME), nullptr);
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController("vmm"), nullptr);
    FreeDummyServerconf(args);
}

/********* Init with empty cri-sandboxers config **********/
TEST_F(ControllerManagerTest, InitTestSucceedWithEmptyConfig)
{
    Errors err;
    const std::string daemonConfig = "{\"cri-sandboxers\": {}}";
    struct service_arguments *args = CreateDummyServerConf(daemonConfig);
    ASSERT_NE(args, nullptr);
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(1).WillOnce(testing::Return(args));
    EXPECT_TRUE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_TRUE(err.Empty());
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController(SHIM_CONTROLLER_NAME), nullptr);
    EXPECT_EQ(ControllerManagerWrapper::GetInstance()->GetController("vmm"), nullptr);
    FreeDummyServerconf(args);
}

/********* Init with empty sandboxer config **********/
TEST_F(ControllerManagerTest, InitTestFailedWithEmptySandboxerConfig)
{
    Errors err;
    const std::string daemonConfig = "{\"cri-sandboxers\": {\"kuasar\": {}}}";
    struct service_arguments *args = CreateDummyServerConf(daemonConfig);
    ASSERT_NE(args, nullptr);
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(1).WillOnce(testing::Return(args));
    EXPECT_FALSE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to load sandboxer controllers config"));
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController(SHIM_CONTROLLER_NAME), nullptr);
    EXPECT_EQ(ControllerManagerWrapper::GetInstance()->GetController("vmm"), nullptr);
    FreeDummyServerconf(args);
}

/********* Init with null sandboxers config **********/
TEST_F(ControllerManagerTest, InitTestSucceedWithNullConfig)
{
    Errors err;
    const std::string daemonConfig = "{}";
    struct service_arguments *args = CreateDummyServerConf(daemonConfig);
    ASSERT_NE(args, nullptr);
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(1).WillOnce(testing::Return(args));
    EXPECT_TRUE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_TRUE(err.Empty());
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController(SHIM_CONTROLLER_NAME), nullptr);
    EXPECT_EQ(ControllerManagerWrapper::GetInstance()->GetController("vmm"), nullptr);
    FreeDummyServerconf(args);
}

/********* Init with dup shim sandboxers config **********/
TEST_F(ControllerManagerTest, InitTestFailedWithDupShimConfig)
{
    Errors err;
    const std::string daemonConfig =
        "{\"cri-sandboxers\": {\"kuasar\": {\"name\": \"shim\",\"address\": \"/run/vmm-sandboxer.sock\"}}}";
    struct service_arguments *args = CreateDummyServerConf(daemonConfig);
    ASSERT_NE(args, nullptr);
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(1).WillOnce(testing::Return(args));
    EXPECT_FALSE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Sandboxer controller already registered, sandboxer:"));
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController(SHIM_CONTROLLER_NAME), nullptr);
    FreeDummyServerconf(args);
}

/********* Init with duplicated runtime handlers sandboxers config *************/
/**
 * If user config with kuasar runtime handler twice with different sandboxer name, both will be registered,
 * but when the user use the same runtime handler, only the first one will be used.
 */
TEST_F(ControllerManagerTest, InitTestFailedWithDupKuasarConfig)
{
    Errors err;
    const std::string daemonConfig =
        "{\"cri-sandboxers\": {\"kuasar\": {\"name\": \"vmm1\",\"address\": \"/run/vmm1-sandboxer.sock\"},\"kuasar\": {\"name\": \"vmm2\",\"address\": \"/run/vmm2-sandboxer.sock\"}}}";
    struct service_arguments *args = CreateDummyServerConf(daemonConfig);
    ASSERT_NE(args, nullptr);
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(1).WillOnce(testing::Return(args));
    EXPECT_TRUE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController("vmm1"), nullptr);
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController("vmm2"), nullptr);
    FreeDummyServerconf(args);
}

/********* Init with dulplicated name in sandboxers config *************/
TEST_F(ControllerManagerTest, InitTestFailedWithDupNameConfig)
{
    Errors err;
    const std::string daemonConfig =
        "{\"cri-sandboxers\": {\"kuasar1\": {\"name\": \"vmm\",\"address\": \"/run/vmm1-sandboxer.sock\"},\"kuasar2\": {\"name\": \"vmm\",\"address\": \"/run/vmm2-sandboxer.sock\"}}}";
    struct service_arguments *args = CreateDummyServerConf(daemonConfig);
    ASSERT_NE(args, nullptr);
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(1).WillOnce(testing::Return(args));
    EXPECT_FALSE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to load sandboxer controllers config"));
    EXPECT_EQ(ControllerManagerWrapper::GetInstance()->GetController("vmm"), nullptr);
    FreeDummyServerconf(args);
}

/********* Init twice *************/
TEST_F(ControllerManagerTest, InitTestFailedWithDupInit)
{
    Errors err;
    const std::string daemonConfig =
        "{\"cri-sandboxers\": {\"kuasar\": {\"name\": \"vmm\",\"address\": \"/run/vmm-sandboxer.sock\"}}}";
    struct service_arguments *args = CreateDummyServerConf(daemonConfig);
    ASSERT_NE(args, nullptr);
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(2).WillRepeatedly(testing::Return(args));
    EXPECT_TRUE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_TRUE(err.Empty());
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController(SHIM_CONTROLLER_NAME), nullptr);
    EXPECT_NE(ControllerManagerWrapper::GetInstance()->GetController("vmm"), nullptr);
    EXPECT_FALSE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Sandboxer controller already registered,"));
    FreeDummyServerconf(args);
}

/********* conf_get_server_conf return null_ptr *************/
TEST_F(ControllerManagerTest, InitTestFailedWithNullConf)
{
    Errors err;
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(1).WillOnce(testing::Return(nullptr));
    EXPECT_FALSE(ControllerManagerWrapper::GetInstance()->Init(err));
    EXPECT_THAT(err.GetCMessage(), testing::HasSubstr("Failed to load sandboxer controllers config"));
}

/********* FindController before init *************/
TEST_F(ControllerManagerTest, FindControllerTestFailedBeforeInit)
{
    Errors err;
    EXPECT_EQ(ControllerManagerWrapper::GetInstance()->GetController(SHIM_CONTROLLER_NAME), nullptr);
    EXPECT_EQ(ControllerManagerWrapper::GetInstance()->GetController("vmm"), nullptr);
}
