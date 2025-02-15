/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: sandbox manager unit test
 * Author: zhongtao
 * Create: 2023-07-20
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <string>

#include "sandbox_mock.h"
#include "isulad_config_mock.h"
#include "sandbox_manager.h"
#include "controller_manager.h"
#include "shim_controller.h"
#include "id_name_manager.h"
#include "utils_file.h"
#include "mock.h"

using ::testing::NiceMock;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::_;

extern "C" {
    DECLARE_WRAPPER_V(util_list_all_subdir, int, (const char *directory, char ***out));
    DEFINE_WRAPPER_V(util_list_all_subdir, int, (const char *directory, char ***out), (directory, out));
}

std::string testId = "451f587884b04ef2a81a6d410f65";
std::string testId2 = "1267423674327443131221424537";

static int util_list_all_subdir_NonEmpty(const char *directory, char ***out)
{

    *out = (char **)(util_smart_calloc_s(sizeof(char *), 1));
    *out[0] = util_strdup_s(testId.c_str());
    return 0;
}

static int util_list_all_subdir_Empty(const char *directory, char ***out)
{
    return 0;
}

static int util_list_all_subdir_Error(const char *directory, char ***out)
{
    return -1;
}

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

namespace sandbox {

class SandboxManagerTest : public testing::Test {
protected:
    void SetUp() override
    {
        m_sandbox = new MockSandbox();
        MockSandbox_SetMock(m_sandbox);
        id_name_manager_init();
        MockIsuladConf_SetMock(isuladConfMock.get());
    }

    void TearDown() override
    {
        MockSandbox_SetMock(nullptr);
        delete m_sandbox;
        id_name_manager_release();
        MockIsuladConf_SetMock(nullptr);
    }

    MockSandbox *m_sandbox;
    std::unique_ptr<MockIsuladConf> isuladConfMock = std::unique_ptr<MockIsuladConf>(new MockIsuladConf());
};

TEST_F(SandboxManagerTest, TestRestoreSandboxes)
{
    Errors error;
    bool result = false;
    std::string testNmae = "test";
    MOCK_SET_V(util_list_all_subdir, util_list_all_subdir_Empty);
    result = SandboxManager::GetInstance()->RestoreSandboxes(error);
    ASSERT_TRUE(result);
    MOCK_CLEAR(util_list_all_subdir);

    MOCK_SET_V(util_list_all_subdir, util_list_all_subdir_Error);
    result = SandboxManager::GetInstance()->RestoreSandboxes(error);
    ASSERT_FALSE(result);
    MOCK_CLEAR(util_list_all_subdir);

    // restore sandbox(id: "451f587884b04ef2a81a6d410f65"; name: "test")
    MOCK_SET_V(util_list_all_subdir, util_list_all_subdir_NonEmpty);
    EXPECT_CALL(*m_sandbox, GetName).Times(2).WillRepeatedly(testing::ReturnRef(testNmae));
    EXPECT_CALL(*m_sandbox, Load).Times(1).WillOnce(testing::Return(true));
    result = SandboxManager::GetInstance()->RestoreSandboxes(error);
    ASSERT_TRUE(result);
}

TEST_F(SandboxManagerTest, TestCreateSandbox)
{
    Errors error;
    int nret = -1;
    size_t rootLen = strlen("/test/rootdir") + 1;
    size_t stateLen = strlen("/test/statedir") + 1;
    std::string netNspath = "/test/nspath";
    std::string name = "test2";
    std::string netMode = "cni";
    std::string testId = "123456";
    std::string emptyStr;
    std::string image = "testImage";
    RuntimeInfo info = {"runc", "shim", "kuasar"};
    auto sandboxConfig = runtime::v1::PodSandboxConfig::default_instance();

    char *rootdir = (char *)util_smart_calloc_s(sizeof(char), rootLen);
    ASSERT_NE(rootdir, nullptr);

    nret = snprintf(rootdir, rootLen, "%s", "/test/rootdir");
    EXPECT_GT(nret, 0);
    EXPECT_LT(nret, rootLen);

    char *statedir = (char *)util_smart_calloc_s(sizeof(char), stateLen);
    ASSERT_NE(statedir, nullptr);

    nret = snprintf(statedir, stateLen, "%s", "/test/rootdir");
    EXPECT_GT(nret, 0);
    EXPECT_LT(nret, stateLen);

    // mock for ControllerManager init
    const std::string daemonConfig =
        "{\"cri-sandboxers\": {\"kuasar\": {\"name\": \"vmm\",\"address\": \"/run/vmm-sandboxer.sock\"}}}";
    struct service_arguments *args = CreateDummyServerConf(daemonConfig);
    ASSERT_NE(args, nullptr);
#ifdef ENABLE_SANDBOXER
    EXPECT_CALL(*isuladConfMock, ConfGetServerConf()).Times(1).WillOnce(testing::Return(args));
#endif
    EXPECT_TRUE(ControllerManager::GetInstance()->Init(error));
    EXPECT_TRUE(error.Empty());

    // testcase for sandbox create fail
    EXPECT_CALL(*isuladConfMock, ConfGetSandboxRootPath()).Times(1).WillOnce(testing::Return(const_cast<char*>(rootdir)));
    EXPECT_CALL(*isuladConfMock, ConfGetSandboxStatePath()).Times(1).WillOnce(testing::Return(const_cast<char*>(statedir)));
    EXPECT_TRUE(SandboxManager::GetInstance()->Init(error));

    auto result = SandboxManager::GetInstance()->CreateSandbox(name, info, emptyStr, netMode, sandboxConfig, image, error);
    ASSERT_EQ(result, nullptr);
    error.Clear();

    result = SandboxManager::GetInstance()->CreateSandbox(name, info, netNspath, emptyStr, sandboxConfig, image, error);
    ASSERT_EQ(result, nullptr);
    error.Clear();

    // testcase for sandbox create success
    // create sandbox(id: randomly generated; name: "test2")
    EXPECT_CALL(*m_sandbox, GetName).Times(1).WillOnce(testing::ReturnRef(name));
    result = SandboxManager::GetInstance()->CreateSandbox(name, info, netNspath, netMode, sandboxConfig, image, error);
    ASSERT_NE(result, nullptr);
    ASSERT_NE(SandboxManager::GetInstance()->GetSandbox(name), nullptr);

    // testcase for sandbox create repeat
    EXPECT_CALL(*m_sandbox, GetId).Times(2).WillRepeatedly(testing::ReturnRef(testId));
    result = SandboxManager::GetInstance()->CreateSandbox(name, info, netNspath, netMode, sandboxConfig, image, error);
    ASSERT_EQ(result, nullptr);
}

TEST_F(SandboxManagerTest, TestGetSandboxes)
{
    std::string prefixId = "451f587";
    std::string testNmae = "test";
    Errors error;

    ASSERT_EQ(SandboxManager::GetInstance()->GetSandbox(""), nullptr);
    ASSERT_NE(SandboxManager::GetInstance()->GetSandbox(testNmae), nullptr);
    ASSERT_NE(SandboxManager::GetInstance()->GetSandbox(testId), nullptr);
    ASSERT_NE(SandboxManager::GetInstance()->GetSandbox(prefixId), nullptr);
}

TEST_F(SandboxManagerTest, TestListAllSandboxes)
{
    runtime::v1::PodSandboxFilter filters;
    std::vector<std::shared_ptr<Sandbox>> sandboxes;
    std::vector<std::shared_ptr<Sandbox>> sandboxesAll;
    // sandbox(id: "451f587884b04ef2a81a6d410f65"; name: "test")
    // sandbox(id: randomly generated; name: "test2")
    SandboxManager::GetInstance()->ListAllSandboxes(filters, sandboxesAll);
    EXPECT_EQ(sandboxesAll.size(), 2);

    runtime::v1::PodSandboxFilter filters1;
    filters1.set_id(testId);
    std::vector<std::shared_ptr<Sandbox>> sandboxes1;
    EXPECT_CALL(*m_sandbox, GetId).WillOnce(testing::ReturnRef(testId)).WillOnce(testing::ReturnRef(testId2));
    SandboxManager::GetInstance()->ListAllSandboxes(filters1, sandboxes1);
    EXPECT_EQ(sandboxes1.size(), 1);

    runtime::v1::PodSandboxFilter filters2;
    filters2.mutable_state()->set_state(runtime::v1::PodSandboxState::SANDBOX_READY);
    std::vector<std::shared_ptr<Sandbox>> sandboxes2;
    EXPECT_CALL(*m_sandbox, IsReady).Times(2).WillRepeatedly(testing::Return(false));
    SandboxManager::GetInstance()->ListAllSandboxes(filters2, sandboxes2);
    EXPECT_EQ(sandboxes2.size(), 0);

    runtime::v1::PodSandboxFilter filters3;
    std::vector<std::shared_ptr<Sandbox>> sandboxes3;
    auto sandboxConfig = runtime::v1::PodSandboxConfig::default_instance();
    auto labels = sandboxConfig.mutable_labels();
    (*labels)["app"] = "mysql";
    filters3.mutable_label_selector()->insert({"app", "nginx"});
    auto expectedConfig = std::make_shared<runtime::v1::PodSandboxConfig>(sandboxConfig);
    EXPECT_CALL(*m_sandbox, GetMutableSandboxConfig()).Times(4).WillRepeatedly(testing::Return(expectedConfig));
    SandboxManager::GetInstance()->ListAllSandboxes(filters3, sandboxes3);
    EXPECT_EQ(sandboxes2.size(), 0);
}

TEST_F(SandboxManagerTest, TestDeleteSandbox)
{
    std::string testNmae = "test";
    Errors error;
    auto result = SandboxManager::GetInstance()->DeleteSandbox("", error);
    ASSERT_FALSE(result);
    error.Clear();

    EXPECT_CALL(*m_sandbox, GetName).Times(1).WillOnce(testing::ReturnRef(testNmae));
    EXPECT_CALL(*m_sandbox, GetId).Times(1).WillOnce(testing::ReturnRef(testId));
    result = SandboxManager::GetInstance()->DeleteSandbox(testId, error);
    ASSERT_TRUE(result);
}
}