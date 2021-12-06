/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: network namespace unit test
 * Author: chengzeruizhi
 * Create: 2021-12-02
 */

#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gtest/gtest.h>
#include "network_namespace_api.h"
#include "specs_namespace.h"
#include "namespace.h"

TEST(network_ns_ut, test_namespace_is_file)
{
    const char *mode1 = (const char *)"file";
    bool res1 = namespace_is_file(mode1);
    EXPECT_TRUE(res1);

    const char *mode2 = (const char *)"file:123456";
    bool res2 = namespace_is_file(mode2);
    EXPECT_FALSE(res2);

    char *mode3 = nullptr;
    bool res3 = namespace_is_file(mode3);
    EXPECT_FALSE(res3);
}

TEST(network_ns_ut, test_namespace_is_bridge)
{
    const char *mode1 = (const char *)"bridge";
    bool res1 = namespace_is_bridge(mode1);
    EXPECT_TRUE(res1);

    const char *mode2 = (const char *)"bridge:123456";
    bool res2 = namespace_is_bridge(mode2);
    EXPECT_FALSE(res2);

    char *mode3 = nullptr;
    bool res3 = namespace_is_bridge(mode3);
    EXPECT_FALSE(res3);
}

TEST(network_ns_ut, test_get_sandbox_key)
{
    // 1. insepct is null
    container_inspect *inspect1 = nullptr;
    char *sandbox_key1 = get_sandbox_key(inspect1);
    EXPECT_TRUE(sandbox_key1 == nullptr);
    free(inspect1);

    // 2. network settings is null
    container_inspect *inspect2 = (container_inspect *)util_common_calloc_s(sizeof(container_inspect));
    char *sandbox_key2 = get_sandbox_key(inspect2);
    EXPECT_TRUE(sandbox_key2 == nullptr);
    free(inspect2);

    // 3. sandboxkey in network settings is null
    container_inspect *inspect3 = (container_inspect *)util_common_calloc_s(sizeof(container_inspect));
    container_network_settings *network_settings3 =
            (container_network_settings *)util_common_calloc_s(sizeof(container_network_settings));
    inspect3->network_settings = network_settings3;
    char *sandbox_key3 = get_sandbox_key(inspect3);
    EXPECT_TRUE(sandbox_key3 == nullptr);
    free(network_settings3);
    free(inspect3);

    // 4. normal cases
    container_inspect *inspect4 = (container_inspect *)util_common_calloc_s(sizeof(container_inspect));
    container_network_settings *network_settings4 =
            (container_network_settings *)util_common_calloc_s(sizeof(container_network_settings));
    inspect4->network_settings = network_settings4;
    network_settings4->sandbox_key = (char *)"isulacni-asdfiyq39084hrfue";
    char *sandbox_key4 = get_sandbox_key(inspect4);
    EXPECT_STREQ(sandbox_key4, "isulacni-asdfiyq39084hrfue");
    free(network_settings4);
    free(inspect4);
}

TEST(network_ns_ut, test_get_network_namespace_path)
{
    // 1. normal cases
    host_config *host_spec = (host_config *)util_common_calloc_s(sizeof(host_config));
    host_spec->network_mode = (char *)"file";
    container_network_settings *settings =
            (container_network_settings *)util_common_calloc_s(sizeof(container_network_settings));
    settings->sandbox_key = (char *)"isulacni-1231rifj";
    char *type = nullptr;
    char *ns_path = nullptr;
    int res = get_network_namespace_path(host_spec, settings, type, &ns_path);
    ASSERT_EQ(res, 0);
    EXPECT_STREQ(ns_path, "isulacni-1231rifj");
    free(host_spec);
    free(settings);

    // 2. no network mode in host spec
    host_config *host_spec1 = (host_config *)util_common_calloc_s(sizeof(host_config));
    container_network_settings *settings1 =
            (container_network_settings *)util_common_calloc_s(sizeof(container_network_settings));
    settings1->sandbox_key = (char *)"isulacni-1231rifj";
    char *type1 = nullptr;
    char *ns_path1 = nullptr;
    int res1 = get_network_namespace_path(host_spec1, settings1, type1, &ns_path1);
    ASSERT_EQ(res1, -1);
    free(host_spec1);
    free(settings1);
}