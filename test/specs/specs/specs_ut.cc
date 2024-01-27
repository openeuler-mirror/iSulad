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
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config.h"
#include "oci_ut_common.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
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

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_1)
{
    ASSERT_EQ(merge_container_cgroups_path(nullptr, nullptr), nullptr);
}

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_2)
{
    host_config *host_spec = nullptr;
    char *merged_cp = nullptr;

    host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    ASSERT_TRUE(host_spec != nullptr);

    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent_null));

    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);

    ASSERT_STREQ(merged_cp, "/isulad/123");

    free_host_config(host_spec);
    free(merged_cp);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_3)
{
    host_config *host_spec = nullptr;
    char *merged_cp = nullptr;

    host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    ASSERT_TRUE(host_spec != nullptr);

    host_spec->cgroup_parent = util_strdup_s("/test");

    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent_null));

    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);

    ASSERT_STREQ(merged_cp, "/test/123");

    free_host_config(host_spec);
    free(merged_cp);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_4)
{
    host_config *host_spec = nullptr;
    char *merged_cp = nullptr;

    host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    ASSERT_TRUE(host_spec != nullptr);

    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent));

    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);

    ASSERT_STREQ(merged_cp, "/var/lib/isulad/engines/lcr/123");

    free_host_config(host_spec);
    free(merged_cp);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, test_merge_container_cgroups_path_5)
{
    host_config *host_spec = nullptr;
    char *merged_cp = nullptr;

    host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    ASSERT_TRUE(host_spec != nullptr);

    host_spec->cgroup_parent = util_strdup_s("/test");

    EXPECT_CALL(m_isulad_conf, GetCgroupParent()).WillRepeatedly(Invoke(invoke_conf_get_isulad_cgroup_parent));

    merged_cp = merge_container_cgroups_path("123", host_spec);
    ASSERT_NE(merged_cp, nullptr);

    ASSERT_STREQ(merged_cp, "/test/123");

    free_host_config(host_spec);
    free(merged_cp);

    testing::Mock::VerifyAndClearExpectations(&m_isulad_conf);
}

TEST_F(SpecsUnitTest, SpecsUnitTest_test_update_devcies_for_oci_spec)
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
