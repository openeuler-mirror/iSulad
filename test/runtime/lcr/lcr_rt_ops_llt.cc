/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Description: lcr runtime ops llt
 * Author: lifeng
 * Create: 2020-02-15
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "lcr_rt_ops.h"
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

class LcrRtOpsUnitTest : public testing::Test {
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

TEST(lcr_rt_ops_llt, test_rt_lcr_detect)
{
    // All parameter NULL
    ASSERT_FALSE(rt_lcr_detect(NULL));

    ASSERT_TRUE(rt_lcr_detect("lcr"));

    ASSERT_TRUE(rt_lcr_detect("LCR"));

    ASSERT_FALSE(rt_lcr_detect("test"));
}

bool RuntimeCreateContainer(const char *id, const char *root, void *config)
{

    if (id == nullptr || root == nullptr) {
        return false;
    }

    return true;
}

bool RuntimeStartContainer(const engine_start_request_t *request)
{

    if (request == nullptr) {
        return false;
    }

    if (request->name == nullptr) {
        return false;
    }

    return true;
}

bool RuntimeCleanContainer(const char *name, const char *lcrpath, const char *logpath, const char *loglevel,
                           pid_t pid)
{

    if (name == nullptr) {
        return false;
    }

    return true;
}

struct engine_operation g_engine_ops;

struct engine_operation *invoke_engines_get_handler(const char *runtime)
{
    if (runtime == nullptr) {
        return nullptr;
    }
    g_engine_ops.engine_create_op = &RuntimeCreateContainer;
    g_engine_ops.engine_start_op = &RuntimeStartContainer;
    g_engine_ops.engine_clean_op = &RuntimeCleanContainer;
    return &g_engine_ops;
}

/* conf get routine rootdir */
char *invoke_conf_get_routine_rootdir(const char *runtime)
{
    if (runtime == nullptr) {
        return nullptr;
    }

    return util_strdup_s("/var/lib/isulad/engines/lcr");
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_create)
{
    rt_create_params_t params = {};

    ASSERT_EQ(rt_lcr_create(nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_create("123", "lcr", &params), 0);

    ASSERT_EQ(rt_lcr_create(nullptr, "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_create("123", nullptr, &params), -1);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

static char *get_absolute_path(const char *file)
{
    char base_path[PATH_MAX] = {0};
    char *json_file = NULL;

    if (getcwd(base_path, PATH_MAX) == NULL) {
        return NULL;
    }

    json_file = util_path_join(base_path, file);
    if (json_file == NULL) {
        return NULL;
    }

    return json_file;
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_start)
{
    rt_start_params_t params = {};
    container_pid_t pid_info = {};
    char *pid_path = get_absolute_path("runtime/lcr/pid.file");

    ASSERT_EQ(rt_lcr_start(nullptr, nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    params.container_pidfile = pid_path;

    ASSERT_EQ(rt_lcr_start("123", "lcr", &params, &pid_info), 0);
    ASSERT_EQ(pid_info.pid, 18715);
    ASSERT_EQ(pid_info.ppid, 18712);
    ASSERT_EQ(pid_info.start_time, 98072004);
    ASSERT_EQ(pid_info.pstart_time, 98072003);

    ASSERT_EQ(rt_lcr_start(nullptr, "lcr", &params, &pid_info), -1);

    ASSERT_EQ(rt_lcr_start("123", nullptr, &params, nullptr), -1);

    free(pid_path);
    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_restart)
{
    ASSERT_EQ(rt_lcr_restart(nullptr, nullptr, nullptr), RUNTIME_NOT_IMPLEMENT_RESET);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_clean_resource)
{
    rt_clean_params_t params = {};

    ASSERT_EQ(rt_lcr_clean_resource(nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_clean_resource("123", "lcr", &params), 0);

    ASSERT_EQ(rt_lcr_clean_resource(nullptr, "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_clean_resource("123", nullptr, &params), -1);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}