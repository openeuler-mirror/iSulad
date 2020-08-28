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
 * Description: lcr runtime ops unit test
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

TEST(lcr_rt_ops_ut, test_rt_lcr_detect)
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

bool RuntimeCleanContainer(const char *name, const char *lcrpath, const char *logpath, const char *loglevel, pid_t pid)
{
    if (name == nullptr) {
        return false;
    }

    return true;
}

bool RuntimeRmContainer(const char *name, const char *enginepath)
{
    if (name == nullptr || enginepath == nullptr) {
        return false;
    }

    return true;
}

int RuntimeStatusContainer(const char *name, const char *enginepath, struct runtime_container_status_info *status)
{
    if (name == nullptr || enginepath == nullptr || status == nullptr) {
        return -1;
    }

    return 0;
}

int RuntimeStatsContainer(const char *name, const char *enginepath,
                          struct runtime_container_resources_stats_info *rs_stats)
{
    if (name == nullptr || enginepath == nullptr || rs_stats == nullptr) {
        return -1;
    }

    return 0;
}

bool RuntimeExecContainer(const engine_exec_request_t *request, int *exit_code)
{
    if (request == nullptr || exit_code == nullptr || request->lcrpath == nullptr) {
        return false;
    }

    return true;
}

bool RuntimePauseContainer(const char *name, const char *enginepath)
{
    if (name == nullptr || enginepath == nullptr) {
        return false;
    }

    return true;
}

bool RuntimeResumeContainer(const char *name, const char *enginepath)
{
    if (name == nullptr || enginepath == nullptr) {
        return false;
    }

    return true;
}

bool RuntimeAttachContainer(const char *name, const char *enginepath, char *in_fifo, char *out_fifo, char *err_fifo)
{
    if (name == nullptr || enginepath == nullptr) {
        return false;
    }

    return true;
}

bool RuntimeUpdateContainer(const char *name, const char *enginepath, const struct engine_cgroup_resources *cr)
{
    if (name == nullptr || enginepath == nullptr) {
        return false;
    }

    return true;
}

bool RuntimeResizeContainer(const char *name, const char *lcrpath, unsigned int height, unsigned int width)
{
    if (name == nullptr || lcrpath == nullptr) {
        return false;
    }

    return true;
}

bool RuntimeExecResizeContainer(const char *name, const char *lcrpath, const char *suffix, unsigned int height,
                                unsigned int width)
{
    if (name == nullptr || lcrpath == nullptr) {
        return false;
    }

    return true;
}

bool RuntimeListPidsContainer(const char *name, const char *rootpath, pid_t **pids, size_t *pids_len)
{
    if (name == nullptr || rootpath == nullptr) {
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
    g_engine_ops.engine_delete_op = &RuntimeRmContainer;
    g_engine_ops.engine_get_container_status_op = &RuntimeStatusContainer;
    g_engine_ops.engine_get_container_resources_stats_op = &RuntimeStatsContainer;
    g_engine_ops.engine_exec_op = &RuntimeExecContainer;
    g_engine_ops.engine_pause_op = &RuntimePauseContainer;
    g_engine_ops.engine_resume_op = &RuntimeResumeContainer;
    g_engine_ops.engine_console_op = &RuntimeAttachContainer;
    g_engine_ops.engine_update_op = &RuntimeUpdateContainer;
    g_engine_ops.engine_resize_op = &RuntimeResizeContainer;
    g_engine_ops.engine_exec_resize_op = &RuntimeExecResizeContainer;
    g_engine_ops.engine_get_container_pids_op = &RuntimeListPidsContainer;

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
    char base_path[PATH_MAX] = { 0 };
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
    pid_ppid_info_t pid_info = {};
    char *pid_path = get_absolute_path("../../../../test/runtime/lcr/pid.file");

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

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_rm)
{
    rt_rm_params_t params = {};

    ASSERT_EQ(rt_lcr_rm(nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_rm("123", "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_rm(nullptr, "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_rm("123", nullptr, &params), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_rm("123", "lcr", &params), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_status)
{
    rt_status_params_t params = {};
    struct runtime_container_status_info status = {};

    ASSERT_EQ(rt_lcr_status(nullptr, nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_status("123", "lcr", &params, nullptr), -1);

    ASSERT_EQ(rt_lcr_status(nullptr, "lcr", &params, &status), -1);

    ASSERT_EQ(rt_lcr_status("123", nullptr, &params, &status), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_status("123", "lcr", &params, nullptr), -1);

    ASSERT_EQ(rt_lcr_status("123", "lcr", &params, &status), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_resources_stats)
{
    rt_stats_params_t params = {};
    struct runtime_container_resources_stats_info status = {};

    ASSERT_EQ(rt_lcr_resources_stats(nullptr, nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_resources_stats("123", "lcr", &params, nullptr), -1);

    ASSERT_EQ(rt_lcr_resources_stats(nullptr, "lcr", &params, &status), -1);

    ASSERT_EQ(rt_lcr_resources_stats("123", nullptr, &params, &status), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_resources_stats("123", "lcr", &params, nullptr), -1);

    ASSERT_EQ(rt_lcr_resources_stats("123", "lcr", &params, &status), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_exec)
{
    rt_exec_params_t params = {};
    int pid = 0;

    ASSERT_EQ(rt_lcr_exec(nullptr, nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_exec("123", "lcr", &params, nullptr), -1);

    ASSERT_EQ(rt_lcr_exec(nullptr, "lcr", &params, &pid), -1);

    ASSERT_EQ(rt_lcr_exec("123", nullptr, &params, &pid), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_exec("123", "lcr", &params, nullptr), -1);

    ASSERT_EQ(rt_lcr_exec("123", "lcr", &params, &pid), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_pause)
{
    rt_pause_params_t params = {};

    ASSERT_EQ(rt_lcr_pause(nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_pause("123", "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_pause(nullptr, "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_pause("123", nullptr, &params), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_pause("123", "lcr", &params), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_resume)
{
    rt_resume_params_t params = {};

    ASSERT_EQ(rt_lcr_resume(nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_resume("123", "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_resume(nullptr, "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_resume("123", nullptr, &params), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_resume("123", "lcr", &params), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_attach)
{
    rt_attach_params_t params = {};

    ASSERT_EQ(rt_lcr_attach(nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_attach("123", "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_attach(nullptr, "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_attach("123", nullptr, &params), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_attach("123", "lcr", &params), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_update)
{
    rt_update_params_t params = {};

    ASSERT_EQ(rt_lcr_update(nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_update("123", "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_update(nullptr, "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_update("123", nullptr, &params), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_update("123", "lcr", &params), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_resize)
{
    rt_resize_params_t params = {};

    ASSERT_EQ(rt_lcr_resize(nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_resize("123", "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_resize(nullptr, "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_resize("123", nullptr, &params), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_resize("123", "lcr", &params), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_exec_resize)
{
    rt_exec_resize_params_t params = {};

    ASSERT_EQ(rt_lcr_exec_resize(nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_exec_resize("123", "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_exec_resize(nullptr, "lcr", &params), -1);

    ASSERT_EQ(rt_lcr_exec_resize("123", nullptr, &params), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_exec_resize("123", "lcr", &params), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(LcrRtOpsUnitTest, test_rt_lcr_listpids)
{
    rt_listpids_params_t params = {};
    rt_listpids_out_t out = {};

    ASSERT_EQ(rt_lcr_listpids(nullptr, nullptr, nullptr, nullptr), -1);

    EXPECT_CALL(m_isulad_conf, GetRuntimeDir(_)).WillRepeatedly(Invoke(invoke_conf_get_routine_rootdir));
    EXPECT_CALL(m_engine, EngineGetHandler(_)).WillRepeatedly(Invoke(invoke_engines_get_handler));

    ASSERT_EQ(rt_lcr_listpids("123", "lcr", &params, nullptr), -1);

    ASSERT_EQ(rt_lcr_listpids(nullptr, "lcr", &params, &out), -1);

    ASSERT_EQ(rt_lcr_listpids("123", nullptr, &params, &out), -1);

    params.rootpath = "/var/lib/isulad";
    ASSERT_EQ(rt_lcr_listpids("123", "lcr", &params, nullptr), -1);

    ASSERT_EQ(rt_lcr_listpids("123", "lcr", &params, &out), 0);

    testing::Mock::VerifyAndClearExpectations(&m_engine);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}
