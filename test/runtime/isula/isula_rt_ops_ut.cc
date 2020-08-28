/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: isula runtime ops unit test
 * Author: jingrui
 * Create: 2020-02-15
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "isula_rt_ops.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "engine_mock.h"
#include "isulad_config_mock.h"
#include "utils.h"

using ::testing::Args;
using ::testing::ByRef;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::NotNull;
using ::testing::AtLeast;
using ::testing::Invoke;
using ::testing::_;

using namespace std;

class IsulaRtOpsUnitTest : public testing::Test {
public:
    void SetUp() override
    {
        MockEngine_SetMock(&m_engine);
        ::testing::Mock::AllowLeak(&m_engine);

        MockIsuladConf_SetMock(&m_isulad_conf);
        ::testing::Mock::AllowLeak(&m_isulad_conf);
    }
    void TearDown() override
    {
        MockEngine_SetMock(nullptr);
        MockIsuladConf_SetMock(nullptr);
    }

    NiceMock<MockEngine> m_engine;
    NiceMock<MockIsuladConf> m_isulad_conf;
};

TEST(isula_rt_ops_ut, test_rt_isula_detect)
{
    // All parameter NULL
    ASSERT_FALSE(rt_isula_detect(NULL));

    ASSERT_TRUE(rt_isula_detect("kata-runtime"));

    ASSERT_TRUE(rt_isula_detect("kata-me"));
    ASSERT_TRUE(rt_isula_detect("runc"));

    ASSERT_FALSE(rt_isula_detect("lcr"));
}

TEST_F(IsulaRtOpsUnitTest, test_rt_isula_create)
{
    ASSERT_EQ(rt_isula_create(nullptr, nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_create("123", nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_create("123", "kata-runtime", nullptr), -1);
}

TEST_F(IsulaRtOpsUnitTest, test_rt_isula_start)
{
    rt_start_params_t params = {};
    ASSERT_EQ(rt_isula_start(nullptr, nullptr, nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_start("123", nullptr, nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_start("123", "kata-runtime", nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_start("123", "kata-runtime", &params, nullptr), -1);
}

TEST_F(IsulaRtOpsUnitTest, test_rt_isula_clean_resource)
{
    rt_clean_params_t params = {};

    ASSERT_EQ(rt_isula_clean_resource(nullptr, nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_clean_resource("123", nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_clean_resource("123", "kata-runtime", nullptr), -1);
    ASSERT_EQ(rt_isula_clean_resource("123", "kata-runtime", &params), -1);
    params.statepath = "/var/run/isulad/kata-runtime/123";
    ASSERT_EQ(rt_isula_clean_resource("123", "kata-runtime", &params), 0);
}

TEST_F(IsulaRtOpsUnitTest, test_rt_isula_rm)
{
    rt_rm_params_t params = {};
    ASSERT_EQ(rt_isula_rm(nullptr, nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_rm("123", nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_rm("123", "kata-runtime", nullptr), -1);
    ASSERT_EQ(rt_isula_rm("123", "kata-runtime", &params), -1);
    params.rootpath = "/var/lib/isulad/kata-runtime/123";
    ASSERT_EQ(rt_isula_rm("123", "kata-runtime", &params), 0);
}

TEST_F(IsulaRtOpsUnitTest, test_rt_isula_exec)
{
    rt_exec_params_t params = {};
    ASSERT_EQ(rt_isula_exec(nullptr, nullptr, nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_exec("123", nullptr, nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_exec("123", "kata-runtime", nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_exec("123", "kata-runtime", &params, nullptr), -1);
}

TEST_F(IsulaRtOpsUnitTest, test_rt_isula_status)
{
    rt_status_params_t params = {};
    struct runtime_container_status_info status = {};
    ASSERT_EQ(rt_isula_status(nullptr, nullptr, nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_status("123", nullptr, nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_status("123", "kata-runtime", nullptr, nullptr), -1);
    ASSERT_EQ(rt_isula_status("123", "kata-runtime", &params, nullptr), -1);
    params.state = "/var/run/isulad/kata-runtime";
    ASSERT_EQ(rt_isula_status("123", "kata-runtime", &params, &status), -1);
}
