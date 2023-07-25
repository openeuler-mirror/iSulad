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
#include "sandbox_manager.h"
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

static int util_list_all_subdir_NonEmpty(const char *directory, char ***out)
{

    *out = (char **)(util_smart_calloc_s(sizeof(char *), 1));
    *out[0] = util_strdup_s("451f587884b04ef2a81a6d410f65");
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

namespace sandbox {

class SandboxManagerTest : public testing::Test {
protected:
    void SetUp() override
    {
        m_sandbox = new MockSandbox();
        MockSandbox_SetMock(m_sandbox);
        id_store_init();
        name_store_init();
    }

    void TearDown() override
    {
        MockSandbox_SetMock(nullptr);
        delete m_sandbox;
        id_store_free();
        name_store_free();

    }

    MockSandbox *m_sandbox;
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

    MOCK_SET_V(util_list_all_subdir, util_list_all_subdir_NonEmpty);
    EXPECT_CALL(*m_sandbox, GetName).Times(1).WillOnce(testing::ReturnRef(testNmae));
    EXPECT_CALL(*m_sandbox, Load).Times(1).WillOnce(testing::Return(true));
    result = SandboxManager::GetInstance()->RestoreSandboxes(error);
    ASSERT_TRUE(result);

    ASSERT_NE(SandboxManager::GetInstance()->GetSandbox("test", error), nullptr);
}
}