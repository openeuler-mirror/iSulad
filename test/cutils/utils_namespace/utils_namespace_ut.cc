/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2022-10-13
 * Description: utils namespace unit test
 *******************************************************************************/

#include <gtest/gtest.h>
#include "namespace.h"

TEST(utils_namespace, test_namespace_is_host)
{
    ASSERT_EQ(namespace_is_host(SHARE_NAMESPACE_HOST), true);
    ASSERT_EQ(namespace_is_host(SHARE_NAMESPACE_NONE), false);
    ASSERT_EQ(namespace_is_host(nullptr), false);
}

TEST(utils_namespace, test_namespace_is_none)
{
    ASSERT_EQ(namespace_is_none(SHARE_NAMESPACE_HOST), false);
    ASSERT_EQ(namespace_is_none(SHARE_NAMESPACE_NONE), true);
    ASSERT_EQ(namespace_is_none(nullptr), false);
}

TEST(utils_namespace, test_namespace_is_container)
{
    std::string con = "container:test";
    ASSERT_EQ(namespace_is_container(SHARE_NAMESPACE_HOST), false);
    ASSERT_EQ(namespace_is_container(con.c_str()), true);
    ASSERT_EQ(namespace_is_container(nullptr), false);
}

TEST(utils_namespace, test_namespace_is_bridge)
{
    ASSERT_EQ(namespace_is_bridge(SHARE_NAMESPACE_HOST), false);
    ASSERT_EQ(namespace_is_bridge(SHARE_NAMESPACE_BRIDGE), true);
    ASSERT_EQ(namespace_is_bridge(nullptr), false);
}

TEST(utils_namespace, test_namespace_is_file)
{
    ASSERT_EQ(namespace_is_file(SHARE_NAMESPACE_HOST), false);
    ASSERT_EQ(namespace_is_file(SHARE_NAMESPACE_FILE), true);
    ASSERT_EQ(namespace_is_file(nullptr), false);
}

TEST(utils_namespace, test_namespace_is_shareable)
{
    ASSERT_EQ(namespace_is_shareable(SHARE_NAMESPACE_HOST), false);
    ASSERT_EQ(namespace_is_shareable(SHARE_NAMESPACE_SHAREABLE), true);
    ASSERT_EQ(namespace_is_shareable(nullptr), false);
}

TEST(utils_namespace, test_namespace_get_connected_container)
{
    std::string con = "container:test";
    char *ret = nullptr;
    ret = namespace_get_connected_container(con.c_str());
    ASSERT_STREQ(ret, "test");
    ASSERT_EQ(namespace_get_connected_container(SHARE_NAMESPACE_SHAREABLE), nullptr);
    ASSERT_EQ(namespace_get_connected_container(nullptr), nullptr);
}

TEST(utils_namespace, test_namespace_get_host_namespace_path)
{
    ASSERT_EQ(namespace_get_host_namespace_path(nullptr), nullptr);
    ASSERT_STREQ(namespace_get_host_namespace_path(TYPE_NAMESPACE_PID), SHARE_NAMESPACE_PID_HOST_PATH);
    ASSERT_STREQ(namespace_get_host_namespace_path(TYPE_NAMESPACE_NETWORK), SHARE_NAMESPACE_NET_HOST_PATH);
    ASSERT_STREQ(namespace_get_host_namespace_path(TYPE_NAMESPACE_IPC), SHARE_NAMESPACE_IPC_HOST_PATH);
    ASSERT_STREQ(namespace_get_host_namespace_path(TYPE_NAMESPACE_UTS), SHARE_NAMESPACE_UTS_HOST_PATH);
    ASSERT_STREQ(namespace_get_host_namespace_path(TYPE_NAMESPACE_MOUNT), SHARE_NAMESPACE_MNT_HOST_PATH);
    ASSERT_STREQ(namespace_get_host_namespace_path(TYPE_NAMESPACE_USER), SHARE_NAMESPACE_USER_HOST_PATH);
    ASSERT_STREQ(namespace_get_host_namespace_path(TYPE_NAMESPACE_CGROUP), SHARE_NAMESPACE_CGROUP_HOST_PATH);
}