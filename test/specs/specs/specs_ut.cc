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
 * Description: specs unit test
 * Author: lifeng
 * Create: 2020-02-18
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "specs_api.h"
#include "specs_mount.h"
#include "specs_namespace.h"
#include "specs_security.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config.h"
#include "oci_ut_common.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "isulad_config_mock.h"
#include "utils.h"
#include "utils_cap.h"

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

static int g_malloc_count = 0;
static int g_malloc_match = 1;

extern "C" {
    DECLARE_WRAPPER_V(util_common_calloc_s, void *, (size_t size));
    DEFINE_WRAPPER_V(util_common_calloc_s, void *, (size_t size), (size));

    DECLARE_WRAPPER_V(util_smart_calloc_s, void *, (size_t size, size_t len));
    DEFINE_WRAPPER_V(util_smart_calloc_s, void *, (size_t size, size_t len), (size, len));

    DECLARE_WRAPPER(get_readonly_default_oci_spec, const oci_runtime_spec *, (bool system_container));
    DEFINE_WRAPPER(get_readonly_default_oci_spec, const oci_runtime_spec *, (bool system_container), (system_container));
}

void *util_common_calloc_s_fail(size_t size)
{
    g_malloc_count++;

    if (g_malloc_count == g_malloc_match) {
        g_malloc_match++;
        g_malloc_count = 0;
        return nullptr;
    } else {
        return __real_util_common_calloc_s(size);
    }
}

void *util_smart_calloc_s_fail(size_t size, size_t len)
{
    g_malloc_count++;

    if (g_malloc_count == g_malloc_match) {
        g_malloc_match++;
        g_malloc_count = 0;
        return nullptr;
    } else {
        return __real_util_smart_calloc_s(size, len);
    }
}

class SpecsUnitTest : public testing::Test {
public:
    void SetUp() override
    {
        MockIsuladConf_SetMock(&m_isulad_conf);
        ::testing::Mock::AllowLeak(&m_isulad_conf);
    }
    void TearDown() override
    {
        MockIsuladConf_SetMock(nullptr);
    }

    NiceMock<MockIsuladConf> m_isulad_conf;
};

#define HOST_CONFIG_FILE "../../../../test/specs/specs/hostconfig.json"
#define OCI_RUNTIME_SPEC_FILE "../../../../test/specs/specs/oci_runtime_spec.json"

TEST(merge_conf_cgroup_ut, test_merge_conf_cgroup_1)
{
    // All parameter nullptr
    ASSERT_NE(merge_conf_cgroup(nullptr, nullptr), 0);
}

TEST(merge_conf_cgroup_ut, test_merge_conf_cgroup_2)
{
    oci_runtime_spec *oci_spec = nullptr;

    // Parameter host_spec is nullptr
    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != nullptr);
    ASSERT_NE(merge_conf_cgroup(oci_spec, nullptr), 0);
    free_oci_runtime_spec(oci_spec);
    oci_spec = nullptr;
}

TEST(merge_conf_cgroup_ut, test_merge_conf_cgroup_3)
{
    char *host_config_file = nullptr;
    host_config *host_spec = nullptr;
    char *err = nullptr;

    // Parameter oci_spec is nullptr
    host_config_file = json_path(HOST_CONFIG_FILE);
    ASSERT_TRUE(host_config_file != nullptr);
    host_spec = host_config_parse_file(host_config_file, nullptr, &err);
    ASSERT_TRUE(host_spec != nullptr);
    free(err);
    err = nullptr;
    free(host_config_file);
    host_config_file = nullptr;
    ASSERT_NE(merge_conf_cgroup(nullptr, host_spec), 0);
    free_host_config(host_spec);
    host_spec = nullptr;
}

TEST(merge_conf_cgroup_ut, test_merge_conf_cgroup)
{
    char *host_config_file = nullptr;
    host_config *host_spec = nullptr;
    oci_runtime_spec *oci_spec = nullptr;
    char *err = nullptr;

    // All parameter correct
    host_config_file = json_path(HOST_CONFIG_FILE);
    ASSERT_TRUE(host_config_file != nullptr);
    host_spec = host_config_parse_file(host_config_file, nullptr, &err);
    ASSERT_TRUE(host_spec != nullptr);
    free(err);
    err = nullptr;
    free(host_config_file);
    host_config_file = nullptr;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != nullptr);

    ASSERT_EQ(merge_conf_cgroup(oci_spec, host_spec), 0);

    free_host_config(host_spec);
    host_spec = nullptr;
    free_oci_runtime_spec(oci_spec);
    oci_spec = nullptr;
}

TEST(merge_conf_cgroup_ut, test_merge_conf_cgroup_cpu)
{
    char *host_config_file = nullptr;
    host_config *host_spec = nullptr;
    char *oci_config_file = nullptr;
    oci_runtime_spec *oci_spec = nullptr;
    char *err = nullptr;

    // cpu
    host_config_file = json_path(HOST_CONFIG_FILE);
    ASSERT_TRUE(host_config_file != nullptr);
    host_spec = host_config_parse_file(host_config_file, nullptr, &err);
    ASSERT_TRUE(host_spec != nullptr);
    free(err);
    err = nullptr;
    free(host_config_file);
    host_config_file = nullptr;

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);
    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);
    err = nullptr;
    free(oci_config_file);
    oci_config_file = nullptr;

    host_spec->cpu_period = 123;
    host_spec->cpu_quota = 234;
    host_spec->cpu_realtime_period = 456;
    host_spec->cpu_realtime_runtime = 789;
    host_spec->cpu_shares = 321;
    free(host_spec->cpuset_cpus);
    host_spec->cpuset_cpus = util_strdup_s("0-3");
    free(host_spec->cpuset_mems);
    host_spec->cpuset_mems = util_strdup_s("0");

    ASSERT_EQ(merge_conf_cgroup(oci_spec, host_spec), 0);

    ASSERT_EQ(oci_spec->linux->resources->cpu->period, 123);
    ASSERT_EQ(oci_spec->linux->resources->cpu->quota, 234);
    ASSERT_EQ(oci_spec->linux->resources->cpu->realtime_period, 456);
    ASSERT_EQ(oci_spec->linux->resources->cpu->realtime_runtime, 789);
    ASSERT_EQ(oci_spec->linux->resources->cpu->shares, 321);
    ASSERT_STREQ(oci_spec->linux->resources->cpu->cpus, "0-3");
    ASSERT_STREQ(oci_spec->linux->resources->cpu->mems, "0");

    free_host_config(host_spec);
    host_spec = nullptr;
    free_oci_runtime_spec(oci_spec);
    oci_spec = nullptr;
}

TEST(merge_conf_cgroup_ut, test_merge_conf_cgroup_mem)
{
    char *host_config_file = nullptr;
    host_config *host_spec = nullptr;
    char *oci_config_file = nullptr;
    oci_runtime_spec *oci_spec = nullptr;
    char *err = nullptr;

    host_config_file = json_path(HOST_CONFIG_FILE);
    ASSERT_TRUE(host_config_file != nullptr);
    host_spec = host_config_parse_file(host_config_file, nullptr, &err);
    ASSERT_TRUE(host_spec != nullptr);
    free(err);
    err = nullptr;
    free(host_config_file);
    host_config_file = nullptr;

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);
    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);
    err = nullptr;
    free(oci_config_file);
    oci_config_file = nullptr;

    host_spec->kernel_memory = 123;
    host_spec->memory_reservation = 234;
    host_spec->memory_swap = 456;

    ASSERT_EQ(merge_conf_cgroup(oci_spec, host_spec), 0);

    ASSERT_EQ(oci_spec->linux->resources->memory->kernel, 123);
    ASSERT_EQ(oci_spec->linux->resources->memory->reservation, 234);
    ASSERT_EQ(oci_spec->linux->resources->memory->swap, 456);

    free_host_config(host_spec);
    host_spec = nullptr;
    free_oci_runtime_spec(oci_spec);
    oci_spec = nullptr;
}

/* conf get routine rootdir */
char *invoke_conf_get_isulad_cgroup_parent_null()
{
    return nullptr;
}

/* conf get routine rootdir */
char *invoke_conf_get_isulad_cgroup_parent()
{
    return util_strdup_s("/var/lib/isulad/engines/lcr");
}

int invoke_conf_get_isulad_default_ulimit_empty(host_config_ulimits_element ***ulimit)
{
    if (ulimit == nullptr) {
        return -1;
    }
    return 0;
}

int invoke_conf_get_isulad_default_ulimit(host_config_ulimits_element ***ulimit)
{
    if (ulimit == nullptr) {
        return -1;
    }
    host_config_ulimits_element *ele = static_cast<host_config_ulimits_element*>(util_common_calloc_s(sizeof(host_config_ulimits_element)));
    if (ele == nullptr) {
        return -1;
    }
    ele->hard = 8192;
    ele->soft = 2048;
    ele->name = util_strdup_s("NPROC");

    int ret = ulimit_array_append(ulimit, ele, ulimit_array_len(*ulimit));
    free_host_config_ulimits_element(ele);
    return ret;
}

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_1)
{
    ASSERT_EQ(merge_container_cgroups_path(nullptr, nullptr), nullptr);
}

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_2)
{
    oci_runtime_spec *oci_spec = nullptr;
    host_config *host_spec = nullptr;
    char *merged_cp = nullptr;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != nullptr);

    host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    ASSERT_TRUE(host_spec != nullptr);

    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent_null));
    EXPECT_CALL(m_isulad_conf, ConfGetSystemdCgroup()).WillRepeatedly(Return(false));

    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);

    ASSERT_STREQ(merged_cp, "/isulad/123");

    free_oci_runtime_spec(oci_spec);
    free_host_config(host_spec);
    free(merged_cp);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_3)
{
    oci_runtime_spec *oci_spec = nullptr;
    host_config *host_spec = nullptr;
    char *merged_cp = nullptr;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != nullptr);

    host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    ASSERT_TRUE(host_spec != nullptr);

    host_spec->cgroup_parent = util_strdup_s("/test");

    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent_null));
    EXPECT_CALL(m_isulad_conf, ConfGetSystemdCgroup()).WillRepeatedly(Return(false));

    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);

    ASSERT_STREQ(merged_cp, "/test/123");

    free_oci_runtime_spec(oci_spec);
    free_host_config(host_spec);
    free(merged_cp);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_4)
{
    oci_runtime_spec *oci_spec = nullptr;
    host_config *host_spec = nullptr;
    char *merged_cp = nullptr;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != nullptr);

    host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    ASSERT_TRUE(host_spec != nullptr);

    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent));
    EXPECT_CALL(m_isulad_conf, ConfGetSystemdCgroup()).WillRepeatedly(Return(false));

    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);

    ASSERT_STREQ(merged_cp, "/var/lib/isulad/engines/lcr/123");

    free_oci_runtime_spec(oci_spec);
    free_host_config(host_spec);
    free(merged_cp);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_5)
{
    oci_runtime_spec *oci_spec = nullptr;
    host_config *host_spec = nullptr;
    char *merged_cp = nullptr;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != nullptr);

    host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    ASSERT_TRUE(host_spec != nullptr);

    host_spec->cgroup_parent = util_strdup_s("/test");

    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent));
    EXPECT_CALL(m_isulad_conf, ConfGetSystemdCgroup()).WillRepeatedly(Return(false));

    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);

    ASSERT_STREQ(merged_cp, "/test/123");

    free_oci_runtime_spec(oci_spec);
    free_host_config(host_spec);
    free(merged_cp);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

// systemd cgroup test
TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_6)
{
    oci_runtime_spec *oci_spec = nullptr;
    host_config *host_spec = nullptr;
    char *merged_cp = nullptr;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != nullptr);

    host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    ASSERT_TRUE(host_spec != nullptr);

    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent_null));
    EXPECT_CALL(m_isulad_conf, ConfGetSystemdCgroup()).WillRepeatedly(Return(true));

    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);
    ASSERT_STREQ(merged_cp, "system.slice:isulad:123");
    free(merged_cp);

    host_spec->cgroup_parent = util_strdup_s("/test");
    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_EQ(merged_cp, nullptr);
    free(host_spec->cgroup_parent);

    host_spec->cgroup_parent = util_strdup_s("test.slice");
    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);
    ASSERT_STREQ(merged_cp, "test.slice:isulad:123");
    free(merged_cp);
    free(host_spec->cgroup_parent);

    host_spec->cgroup_parent = util_strdup_s("test/test-a/test-a-b.slice");
    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);
    ASSERT_STREQ(merged_cp, "test-a-b.slice:isulad:123");

    free_oci_runtime_spec(oci_spec);
    free_host_config(host_spec);
    free(merged_cp);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, test_update_oci_container_cgroups_path)
{
    parser_error err = nullptr;
    host_config *hostspec = static_cast<host_config *>(util_common_calloc_s(sizeof(host_config)));
    ASSERT_NE(hostspec, nullptr);

    oci_runtime_spec *ocispec = oci_runtime_spec_parse_data("{\"ociVersion\": \"1.0.1\", \"linux\": \
                                                                {} }", nullptr, &err);
    ASSERT_NE(ocispec, nullptr);

    ocispec->linux->cgroups_path = util_strdup_s("/isulad");
    ASSERT_EQ(update_oci_container_cgroups_path("abcdef", nullptr, nullptr), -1);
    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent));
    ASSERT_EQ(update_oci_container_cgroups_path("abcdef", ocispec, hostspec), 0);
    ASSERT_STREQ(ocispec->linux->cgroups_path, "/var/lib/isulad/engines/lcr/abcdef");

    free(err);
    free_host_config(hostspec);
    free_oci_runtime_spec(ocispec);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, test_update_oci_ulimit)
{
    parser_error err = nullptr;
    host_config *hostspec = static_cast<host_config *>(util_common_calloc_s(sizeof(host_config)));
    ASSERT_NE(hostspec, nullptr);

    char *oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);
    oci_runtime_spec *ocispec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_NE(ocispec, nullptr);

    ASSERT_EQ(update_oci_ulimit(nullptr, nullptr), -1);
    EXPECT_CALL(m_isulad_conf, GetUlimit(_)).WillRepeatedly(Invoke(invoke_conf_get_isulad_default_ulimit));
    ASSERT_EQ(update_oci_ulimit(ocispec, hostspec), 0);
    ASSERT_EQ(ocispec->process->rlimits_len, 1);
    ASSERT_EQ(ocispec->process->rlimits[0]->hard, 8192);
    ASSERT_EQ(ocispec->process->rlimits[0]->soft, 2048);
    ASSERT_STREQ(ocispec->process->rlimits[0]->type, "RLIMIT_NPROC");
    EXPECT_CALL(m_isulad_conf, GetUlimit(_)).WillRepeatedly(Invoke(invoke_conf_get_isulad_default_ulimit_empty));
    ASSERT_EQ(update_oci_ulimit(ocispec, hostspec), 0);
    ASSERT_EQ(ocispec->process->rlimits_len, 0);

    free(err);
    free(oci_config_file);
    free_host_config(hostspec);
    free_oci_runtime_spec(ocispec);
    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, test_update_devcies_for_oci_spec)
{
    parser_error err = nullptr;
    oci_runtime_spec *readonly_spec = oci_runtime_spec_parse_data("{\"ociVersion\": \"1.0.1\", \"linux\": \
                                                                { \"devices\": \
                                                                 [ { \"type\": \"c\", \"path\": \"/dev/testA\", \
                                                                    \"fileMode\": 8612, \"major\": 99, \"minor\": 99} ], \
                                                                 \"resources\": { \"devices\": [ { \"allow\": false, \
					                                                              \"type\": \"a\", \"major\": -1, \
					                                                              \"minor\": -1, \"access\": \"rwm\" } ] } } }", nullptr, &err);
    ASSERT_NE(readonly_spec, nullptr);
    free(err);
    err = nullptr;
    host_config *hostspec = static_cast<host_config *>(util_common_calloc_s(sizeof(host_config)));
    ASSERT_NE(hostspec, nullptr);

    oci_runtime_spec *ocispec = oci_runtime_spec_parse_data("{\"ociVersion\": \"1.0.1\", \"linux\": \
                                                                { \"devices\": [  ], \
                                                                 \"resources\": { \"devices\": [ ] } } }", nullptr, &err);
    ASSERT_NE(ocispec, nullptr);

    MOCK_SET(get_readonly_default_oci_spec, readonly_spec);
    MOCK_SET_V(util_smart_calloc_s, util_smart_calloc_s_fail);
    MOCK_SET_V(util_common_calloc_s, util_common_calloc_s_fail);

    ASSERT_EQ(update_devcies_for_oci_spec(ocispec, hostspec), -1);
    ASSERT_EQ(update_devcies_for_oci_spec(ocispec, hostspec), -1);
    ASSERT_EQ(update_devcies_for_oci_spec(ocispec, hostspec), -1);
    free(ocispec->linux->devices[0]);
    free(ocispec->linux->devices);
    ocispec->linux->devices = NULL;
    ocispec->linux->devices_len = 0;
    ASSERT_EQ(update_devcies_for_oci_spec(ocispec, hostspec), -1);
    free(ocispec->linux->devices[0]);
    free(ocispec->linux->devices);
    ocispec->linux->devices = NULL;
    ocispec->linux->devices_len = 0;
    ASSERT_EQ(update_devcies_for_oci_spec(ocispec, hostspec), 0);

    MOCK_CLEAR(get_readonly_default_oci_spec);
    MOCK_CLEAR(util_smart_calloc_s);
    MOCK_CLEAR(util_common_calloc_s);

    free_oci_runtime_spec(readonly_spec);
    free_oci_runtime_spec(ocispec);
    free_host_config(hostspec);
    free(err);
}

#ifdef ENABLE_CDI
TEST_F(SpecsUnitTest, test_defs_process_add_multiple_env)
{
    size_t env_len = 2;
    char **envs = (char **)util_common_calloc_s(sizeof(char *) * env_len);
    ASSERT_NE(envs, nullptr);
    defs_process *dp = (defs_process *)util_common_calloc_s(sizeof(defs_process));
    ASSERT_NE(dp, nullptr);
    dp->env_len = 1;
    dp->env = (char **)util_common_calloc_s(sizeof(char *) * dp->env_len);
    ASSERT_NE(dp->env, nullptr);
    
    envs[0] = util_strdup_s("key0=value0");
    envs[1] = util_strdup_s("key1=value1");
    dp->env[0] = util_strdup_s("key0=value0_old");
    ASSERT_EQ(defs_process_add_multiple_env(dp, (const char **)envs, env_len), 0);
    ASSERT_EQ(dp->env_len, 2);
    ASSERT_EQ(strcmp(dp->env[0], envs[0]), 0);
    ASSERT_EQ(strcmp(dp->env[1], envs[1]), 0);

    ASSERT_EQ(defs_process_add_multiple_env(dp, nullptr, env_len), 0);
    ASSERT_EQ(defs_process_add_multiple_env(dp, (const char **)envs, 0), 0);
    ASSERT_EQ(defs_process_add_multiple_env(nullptr, (const char **)envs, env_len), -1);

    free(envs[0]);
    envs[0] = util_strdup_s("=value0");
    ASSERT_EQ(defs_process_add_multiple_env(dp, (const char **)envs, env_len), -1);
    free(envs[0]);
    envs[0] = util_strdup_s("key0=");
    ASSERT_EQ(defs_process_add_multiple_env(dp, (const char **)envs, env_len), 0);
    free(envs[0]);
    envs[0] = util_strdup_s("key0xxxx");
    ASSERT_EQ(defs_process_add_multiple_env(dp, (const char **)envs, env_len), 0);

    free(dp->env[0]);
    dp->env[0] = util_strdup_s("=value0");
    ASSERT_EQ(defs_process_add_multiple_env(dp, (const char **)envs, env_len), -1);
    free(dp->env[0]);
    dp->env[0] = util_strdup_s("key0=");
    ASSERT_EQ(defs_process_add_multiple_env(dp, (const char **)envs, env_len), 0);
    free(dp->env[0]);
    dp->env[0] = util_strdup_s("key0xxxx");
    ASSERT_EQ(defs_process_add_multiple_env(dp, (const char **)envs, env_len), 0);

    free_defs_process(dp);
    free(envs[0]);
    free(envs[1]);
    free(envs);
}

TEST_F(SpecsUnitTest, test_spec_add_multiple_process_env)
{
    size_t env_len = 2;
    char **envs = (char **)util_common_calloc_s(sizeof(char *) * env_len);
    ASSERT_NE(envs, nullptr);
    oci_runtime_spec *oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_NE(oci_spec, nullptr);
    oci_spec->process = (defs_process *)util_common_calloc_s(sizeof(defs_process));
    ASSERT_NE(oci_spec->process, nullptr);
    oci_spec->process->env_len = 1;
    oci_spec->process->env = (char **)util_common_calloc_s(sizeof(char *) * oci_spec->process->env_len);
    ASSERT_NE(oci_spec->process->env, nullptr);
    
    envs[0] = util_strdup_s("key0=value0");
    envs[1] = util_strdup_s("key1=value1");
    oci_spec->process->env[0] = util_strdup_s("key0=value0_old");
    ASSERT_EQ(spec_add_multiple_process_env(oci_spec, (const char **)envs, env_len), 0);
    ASSERT_EQ(oci_spec->process->env_len, 2);
    ASSERT_EQ(strcmp(oci_spec->process->env[0], envs[0]), 0);
    ASSERT_EQ(strcmp(oci_spec->process->env[1], envs[1]), 0);

    ASSERT_EQ(spec_add_multiple_process_env(oci_spec, nullptr, env_len), 0);
    ASSERT_EQ(spec_add_multiple_process_env(oci_spec, (const char **)envs, 0), 0);
    ASSERT_EQ(spec_add_multiple_process_env(nullptr, (const char **)envs, env_len), -1);

    free(envs[0]);
    envs[0] = util_strdup_s("=value0");
    ASSERT_EQ(spec_add_multiple_process_env(oci_spec, (const char **)envs, env_len), -1);
    free(envs[0]);
    envs[0] = util_strdup_s("key0=");
    ASSERT_EQ(spec_add_multiple_process_env(oci_spec, (const char **)envs, env_len), 0);
    free(envs[0]);
    envs[0] = util_strdup_s("key0xxxx");
    ASSERT_EQ(spec_add_multiple_process_env(oci_spec, (const char **)envs, env_len), 0);

    free(oci_spec->process->env[0]);
    oci_spec->process->env[0] = util_strdup_s("=value0");
    ASSERT_EQ(spec_add_multiple_process_env(oci_spec, (const char **)envs, env_len), -1);
    free(oci_spec->process->env[0]);
    oci_spec->process->env[0] = util_strdup_s("key0=");
    ASSERT_EQ(spec_add_multiple_process_env(oci_spec, (const char **)envs, env_len), 0);
    free(oci_spec->process->env[0]);
    oci_spec->process->env[0] = util_strdup_s("key0xxxx");
    ASSERT_EQ(spec_add_multiple_process_env(oci_spec, (const char **)envs, env_len), 0);

    free_oci_runtime_spec(oci_spec);
    free(envs[0]);
    free(envs[1]);
    free(envs);
}

TEST_F(SpecsUnitTest, test_spec_add_device)
{
    defs_device *device = (defs_device *)util_common_calloc_s(sizeof(defs_device));
    ASSERT_NE(device, nullptr);
    oci_runtime_spec *oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_NE(oci_spec, nullptr);
    oci_spec->linux = (oci_runtime_config_linux *)util_common_calloc_s(sizeof(oci_runtime_config_linux));
    ASSERT_NE(oci_spec->linux, nullptr);
    oci_spec->linux->devices_len = 1;
    oci_spec->linux->devices = (defs_device **)util_common_calloc_s(sizeof(defs_device *) * oci_spec->linux->devices_len);
    ASSERT_NE(oci_spec->linux->devices, nullptr);

    device->path = util_strdup_s("/device/path");
    oci_spec->linux->devices[0] = (defs_device *)util_common_calloc_s(sizeof(defs_device));
    ASSERT_NE(oci_spec->linux->devices[0], nullptr);
    oci_spec->linux->devices[0]->path = util_strdup_s("/device/path");
    ASSERT_EQ(spec_add_device(oci_spec, device), 0);
    ASSERT_EQ(oci_spec->linux->devices[0], device);

    oci_spec->linux->devices[0] = nullptr;
    oci_spec->linux->devices_len = 0;
    ASSERT_EQ(spec_add_device(oci_spec, device), 0);
    ASSERT_EQ(oci_spec->linux->devices_len, 1);
    ASSERT_EQ(oci_spec->linux->devices[0], device);

    ASSERT_EQ(spec_add_device(oci_spec, nullptr), -1);
    ASSERT_EQ(spec_add_device(nullptr, device), -1);

    free_oci_runtime_spec(oci_spec);
}

TEST_F(SpecsUnitTest, test_spec_add_linux_resources_device)
{
    oci_runtime_spec *oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_NE(oci_spec, nullptr);
    oci_spec->linux = (oci_runtime_config_linux *)util_common_calloc_s(sizeof(oci_runtime_config_linux));
    ASSERT_NE(oci_spec->linux, nullptr);
    oci_spec->linux->resources = (defs_resources *)util_common_calloc_s(sizeof(defs_resources));
    ASSERT_NE(oci_spec->linux->resources, nullptr);
    oci_spec->linux->resources->devices_len = 1;
    oci_spec->linux->resources->devices = (defs_device_cgroup **)util_common_calloc_s(sizeof(defs_device_cgroup *) * oci_spec->linux->resources->devices_len);
    ASSERT_NE(oci_spec->linux->resources->devices, nullptr);

    oci_spec->linux->resources->devices[0] = (defs_device_cgroup *)util_common_calloc_s(sizeof(defs_device_cgroup));
    ASSERT_NE(oci_spec->linux->resources->devices[0], nullptr);
    ASSERT_EQ(spec_add_linux_resources_device(oci_spec, true, "bind", 10, 9, "rwm"), 0);
    ASSERT_EQ(oci_spec->linux->resources->devices_len, 2);
    ASSERT_EQ(oci_spec->linux->resources->devices[1]->allow, true);
    ASSERT_EQ(strcmp(oci_spec->linux->resources->devices[1]->type, "bind"), 0);
    ASSERT_EQ(oci_spec->linux->resources->devices[1]->major, 10);
    ASSERT_EQ(oci_spec->linux->resources->devices[1]->minor, 9);
    ASSERT_EQ(strcmp(oci_spec->linux->resources->devices[1]->access, "rwm"), 0);

    ASSERT_EQ(spec_add_linux_resources_device(nullptr, true, "bind", 10, 9, "rwm"), -1);

    free_oci_runtime_spec(oci_spec);
}

TEST_F(SpecsUnitTest, test_spec_remove_mount)
{
    oci_runtime_spec *oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_NE(oci_spec, nullptr);
    oci_spec->mounts_len = 2;
    oci_spec->mounts = (defs_mount **)util_common_calloc_s(sizeof(defs_mount *) * oci_spec->mounts_len);
    ASSERT_NE(oci_spec->mounts, nullptr);

    oci_spec->mounts[0] = (defs_mount *)util_common_calloc_s(sizeof(defs_mount));
    ASSERT_NE(oci_spec->mounts[0], nullptr);
    oci_spec->mounts[1] = (defs_mount *)util_common_calloc_s(sizeof(defs_mount));
    ASSERT_NE(oci_spec->mounts[1], nullptr);
    oci_spec->mounts[0]->destination = util_strdup_s("/mount/path/0");
    oci_spec->mounts[1]->destination = util_strdup_s("/mount/path/1");
    spec_remove_mount(oci_spec, oci_spec->mounts[0]->destination);
    ASSERT_EQ(oci_spec->mounts_len, 1);
    ASSERT_EQ(strcmp(oci_spec->mounts[0]->destination, "/mount/path/1"), 0);

    free_oci_runtime_spec(oci_spec);
}

TEST_F(SpecsUnitTest, test_spec_add_mount)
{
    defs_mount *mnt = (defs_mount *)util_common_calloc_s(sizeof(defs_mount));
    ASSERT_NE(mnt, nullptr);
    oci_runtime_spec *oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_NE(oci_spec, nullptr);
    oci_spec->mounts_len = 1;
    oci_spec->mounts = (defs_mount **)util_common_calloc_s(sizeof(defs_mount *) * oci_spec->mounts_len );
    ASSERT_NE(oci_spec->mounts, nullptr);

    oci_spec->mounts[0] = (defs_mount *)util_common_calloc_s(sizeof(defs_mount));
    ASSERT_NE(oci_spec->mounts[0], nullptr);
    oci_spec->mounts[0]->destination = util_strdup_s("/mount/path/0");
    ASSERT_EQ(spec_add_mount(oci_spec, mnt), 0);
    ASSERT_EQ(oci_spec->mounts_len, 2);
    ASSERT_EQ(oci_spec->mounts[1], mnt);

    ASSERT_EQ(spec_add_mount(nullptr, mnt), -1);
    ASSERT_EQ(spec_add_mount(oci_spec, nullptr), -1);

    free_oci_runtime_spec(oci_spec);
}

#define TEST_SPEC_ADD_HOOKS_ITEM_DEF(hooktype)                                                                                  \
    void test_spec_add_##hooktype##_hook(void)                                                                                  \
    {                                                                                                                           \
        defs_hook *hook = (defs_hook *)util_common_calloc_s(sizeof(defs_hook));                                                 \
        ASSERT_NE(hook, nullptr);                                                                                               \
        oci_runtime_spec *oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));                        \
        ASSERT_NE(oci_spec, nullptr);                                                                                           \
        oci_spec->hooks = (oci_runtime_spec_hooks *)util_common_calloc_s(sizeof(oci_runtime_spec_hooks));                        \
        ASSERT_NE(oci_spec->hooks, nullptr);                                                                                           \
        oci_spec->hooks->hooktype##_len = 1;                                                                                    \
        oci_spec->hooks->hooktype = (defs_hook **)util_common_calloc_s(sizeof(defs_hook *) * oci_spec->hooks->hooktype##_len);  \
        ASSERT_NE(oci_spec->hooks->hooktype, nullptr);                                                                          \
                                                                                                                                \
        oci_spec->hooks->hooktype[0] = (defs_hook *)util_common_calloc_s(sizeof(defs_hook));                                    \
        ASSERT_NE(oci_spec->hooks->hooktype[0], nullptr);                                                                       \
        ASSERT_EQ(spec_add_##hooktype##_hook(oci_spec, hook), 0);                                                               \
        ASSERT_EQ(oci_spec->hooks->hooktype##_len, 2);                                                                          \
        ASSERT_EQ(oci_spec->hooks->hooktype[1], hook);                                                                          \
                                                                                                                                \
        ASSERT_EQ(spec_add_##hooktype##_hook(nullptr, hook), -1);                                                               \
        ASSERT_EQ(spec_add_##hooktype##_hook(oci_spec, nullptr), -1);                                                           \
                                                                                                                                \
        free_oci_runtime_spec(oci_spec);                                                                                        \
    }

TEST_SPEC_ADD_HOOKS_ITEM_DEF(prestart)
TEST_SPEC_ADD_HOOKS_ITEM_DEF(poststart)
TEST_SPEC_ADD_HOOKS_ITEM_DEF(poststop)

TEST_F(SpecsUnitTest, test_spec_add_hook)
{
    test_spec_add_prestart_hook();
    test_spec_add_poststart_hook();
    test_spec_add_poststop_hook();
}

#endif /* ENABLE_CDI */

/********************************* UT for merge caps *******************************************/
struct capabilities_lens {
    size_t bounding_len;
    size_t effective_len;
    size_t inheritable_len;
    size_t permitted_len;
    size_t ambient_len;
};

void check_capabilities_len(defs_process_capabilities *cap, struct capabilities_lens *lens)
{
    lens->bounding_len = cap->bounding_len;
    lens->effective_len = cap->effective_len;
    lens->inheritable_len = cap->inheritable_len;
    lens->permitted_len = cap->permitted_len;
    lens->ambient_len = cap->ambient_len;
}

void validate_capabilities_len(defs_process_capabilities *cap, struct capabilities_lens *lens, ssize_t len_diff)
{
    ASSERT_EQ((ssize_t)cap->bounding_len, (ssize_t)lens->bounding_len + len_diff);
    ASSERT_EQ((ssize_t)cap->effective_len, (ssize_t)lens->effective_len + len_diff);
    ASSERT_EQ((ssize_t)cap->permitted_len, (ssize_t)lens->permitted_len + len_diff);
    // Currently we don't support inheritable and ambient capabilities
}

TEST(merge_capability_ut, test_merge_caps_without_adds_drops)
{
    oci_runtime_spec *oci_spec = nullptr;
    int ret = 0;
    char *err = nullptr;
    struct capabilities_lens old_lens = { 0 };
    char *oci_config_file = nullptr;

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);


    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);

    check_capabilities_len(oci_spec->process->capabilities, &old_lens);

    ret = merge_caps(oci_spec, nullptr, 0, nullptr, 0);
    ASSERT_EQ(ret, 0);

    validate_capabilities_len(oci_spec->process->capabilities, &old_lens, 0);

    free_oci_runtime_spec(oci_spec);
}

TEST(merge_capability_ut, test_merge_caps_adds_without_drops)
{
    oci_runtime_spec *oci_spec = nullptr;
    int ret = 0;
    char *err = nullptr;
    struct capabilities_lens old_lens = { 0 };
    char *oci_config_file = nullptr;
    /* All of below capabilities are not in oci_config_file */
    const char *adds[] = { "NET_ADMIN", "SYS_ADMIN", "SYS_TTY_CONFIG", "SYS_PTRACE" };
    const char *drops[] = {};
    size_t adds_len = sizeof(adds) / sizeof(adds[0]);
    size_t drops_len = sizeof(drops) / sizeof(drops[0]);

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);


    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);

    check_capabilities_len(oci_spec->process->capabilities, &old_lens);

    ret = merge_caps(oci_spec, adds, adds_len, drops, drops_len);
    ASSERT_EQ(ret, 0);

    /* All of capabilities in adds are added */
    validate_capabilities_len(oci_spec->process->capabilities, &old_lens, adds_len);

    free_oci_runtime_spec(oci_spec);
}

TEST(merge_capability_ut, test_merge_caps_adds_existing_without_drops)
{
    oci_runtime_spec *oci_spec = nullptr;
    int ret = 0;
    char *err = nullptr;
    struct capabilities_lens old_lens = { 0 };
    char *oci_config_file = nullptr;
    /* CHOWN already exits in oci_config_file */
    const char *adds[] = { "CHOWN", "SYS_ADMIN", "SYS_TTY_CONFIG", "SYS_PTRACE" };
    const char *drops[] = {};
    size_t adds_len = sizeof(adds) / sizeof(adds[0]);
    size_t drops_len = sizeof(drops) / sizeof(drops[0]);

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);


    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);

    check_capabilities_len(oci_spec->process->capabilities, &old_lens);

    ret = merge_caps(oci_spec, adds, adds_len, drops, drops_len);
    ASSERT_EQ(ret, 0);

    /* CHOWN is not added, since it already exits in the default list */
    validate_capabilities_len(oci_spec->process->capabilities, &old_lens, adds_len - 1);

    free_oci_runtime_spec(oci_spec);
}

TEST(merge_capability_ut, test_merge_caps_drops_without_adds)
{
    oci_runtime_spec *oci_spec = nullptr;
    int ret = 0;
    char *err = nullptr;
    struct capabilities_lens old_lens = { 0 };
    char *oci_config_file = nullptr;
    const char *adds[] = {};
    /* Below capabilities are not in the oci_config_file */
    const char *drops[] = { "SYS_TTY_CONFIG", "SYS_PTRACE" };
    size_t adds_len = sizeof(adds) / sizeof(adds[0]);
    size_t drops_len = sizeof(drops) / sizeof(drops[0]);

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);


    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);

    check_capabilities_len(oci_spec->process->capabilities, &old_lens);

    ret = merge_caps(oci_spec, adds, adds_len, drops, drops_len);
    ASSERT_EQ(ret, 0);

    /* Nothing dropped */
    validate_capabilities_len(oci_spec->process->capabilities, &old_lens, 0);

    free_oci_runtime_spec(oci_spec);
}

TEST(merge_capability_ut, test_merge_caps_drops_existing_without_adds)
{
    oci_runtime_spec *oci_spec = nullptr;
    int ret = 0;
    char *err = nullptr;
    struct capabilities_lens old_lens = { 0 };
    char *oci_config_file = nullptr;
    const char *adds[] = {};
    /* Below capabilities are in the oci_config_file */
    const char *drops[] = { "CHOWN", "MKNOD" };
    size_t adds_len = sizeof(adds) / sizeof(adds[0]);
    size_t drops_len = sizeof(drops) / sizeof(drops[0]);

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);


    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);

    check_capabilities_len(oci_spec->process->capabilities, &old_lens);

    ret = merge_caps(oci_spec, adds, adds_len, drops, drops_len);
    ASSERT_EQ(ret, 0);

    /* All dropped */
    validate_capabilities_len(oci_spec->process->capabilities, &old_lens, adds_len - drops_len);

    free_oci_runtime_spec(oci_spec);
}

TEST(merge_capability_ut, test_merge_caps_adds_drops)
{
    oci_runtime_spec *oci_spec = nullptr;
    int ret = 0;
    char *err = nullptr;
    struct capabilities_lens old_lens = { 0 };
    char *oci_config_file = nullptr;
    /* All of below capabilities are not in oci_config_file */
    const char *adds[] = { "NET_ADMIN", "SYS_ADMIN", "SYS_TTY_CONFIG", "SYS_PTRACE" };
    const char *drops[] = { "SYS_TTY_CONFIG", "SYS_PTRACE" };
    size_t adds_len = sizeof(adds) / sizeof(adds[0]);
    size_t drops_len = sizeof(drops) / sizeof(drops[0]);

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);


    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);

    check_capabilities_len(oci_spec->process->capabilities, &old_lens);

    ret = merge_caps(oci_spec, adds, adds_len, drops, drops_len);
    ASSERT_EQ(ret, 0);

    validate_capabilities_len(oci_spec->process->capabilities, &old_lens, adds_len - drops_len);

    free_oci_runtime_spec(oci_spec);
}

TEST(merge_capability_ut, test_merge_caps_adds_all_without_drops)
{
    oci_runtime_spec *oci_spec = nullptr;
    int ret = 0;
    char *err = nullptr;
    struct capabilities_lens old_lens = { 0 };
    char *oci_config_file = nullptr;
    /* NET_ADMIN is in all */
    const char *adds[] = { "ALL", "NET_ADMIN" };
    const char *drops[] = {};
    size_t adds_len = sizeof(adds) / sizeof(adds[0]);
    size_t drops_len = sizeof(drops) / sizeof(drops[0]);
    size_t all_caps_len = 0;
    util_get_all_caps(&all_caps_len);

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);

    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);

    check_capabilities_len(oci_spec->process->capabilities, &old_lens);

    ret = merge_caps(oci_spec, adds, adds_len, drops, drops_len);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(oci_spec->process->capabilities->bounding_len, all_caps_len);
    ASSERT_EQ(oci_spec->process->capabilities->effective_len, all_caps_len);
    ASSERT_EQ(oci_spec->process->capabilities->permitted_len, all_caps_len);

    free_oci_runtime_spec(oci_spec);
}

TEST(merge_capability_ut, test_merge_caps_adds_all_and_extra_without_drops)
{
    oci_runtime_spec *oci_spec = nullptr;
    int ret = 0;
    char *err = nullptr;
    struct capabilities_lens old_lens = { 0 };
    char *oci_config_file = nullptr;
    /* ABC is not in all */
    const char *adds[] = { "ALL", "ABC" };
    const char *drops[] = {};
    size_t adds_len = sizeof(adds) / sizeof(adds[0]);
    size_t drops_len = sizeof(drops) / sizeof(drops[0]);
    size_t all_caps_len = 0;
    util_get_all_caps(&all_caps_len);

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);

    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);

    check_capabilities_len(oci_spec->process->capabilities, &old_lens);

    ret = merge_caps(oci_spec, adds, adds_len, drops, drops_len);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(oci_spec->process->capabilities->bounding_len, all_caps_len + 1);
    ASSERT_EQ(oci_spec->process->capabilities->effective_len, all_caps_len + 1);
    ASSERT_EQ(oci_spec->process->capabilities->permitted_len, all_caps_len + 1);

    free_oci_runtime_spec(oci_spec);
}

TEST(merge_capability_ut, test_merge_caps_adds_all_drops_all)
{
    oci_runtime_spec *oci_spec = nullptr;
    int ret = 0;
    char *err = nullptr;
    struct capabilities_lens old_lens = { 0 };
    char *oci_config_file = nullptr;
    /* ABC, EFG is not in all */
    const char *adds[] = { "ALL", "ABC", "EFG"};
    const char *drops[] = { "ALL", "ABC" };
    size_t adds_len = sizeof(adds) / sizeof(adds[0]);
    size_t drops_len = sizeof(drops) / sizeof(drops[0]);
    size_t all_caps_len = 0;
    util_get_all_caps(&all_caps_len);

    oci_config_file = json_path(OCI_RUNTIME_SPEC_FILE);
    ASSERT_TRUE(oci_config_file != nullptr);

    oci_spec = oci_runtime_spec_parse_file(oci_config_file, nullptr, &err);
    ASSERT_TRUE(oci_spec != nullptr);
    free(err);

    check_capabilities_len(oci_spec->process->capabilities, &old_lens);

    ret = merge_caps(oci_spec, adds, adds_len, drops, drops_len);
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(oci_spec->process->capabilities->bounding_len, 1);
    ASSERT_EQ(oci_spec->process->capabilities->effective_len, 1);
    ASSERT_EQ(oci_spec->process->capabilities->permitted_len, 1);

    free_oci_runtime_spec(oci_spec);
}
