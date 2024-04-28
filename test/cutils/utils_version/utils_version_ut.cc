/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuxu
 * Create: 2024-04-25
 * Description: utils version unit test
 *******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <climits>
#include <gtest/gtest.h>
#include "mock.h"
#include "utils_version.h"
#include "utils.h"

TEST(utils_version, test_util_version_compare)
{
    const char *version1 = "1.1.1";
    const char *version2 = "1.1.2";
    int diff_value = 0;

    ASSERT_EQ(util_version_compare(version1, version2, &diff_value), 0);
    ASSERT_TRUE(diff_value < 0);
    ASSERT_EQ(util_version_compare(version1, version1, &diff_value), 0);
    ASSERT_TRUE(diff_value == 0);
    ASSERT_EQ(util_version_compare(version2, version1, &diff_value), 0);
    ASSERT_TRUE(diff_value > 0);

    ASSERT_EQ(util_version_compare(version1, nullptr, &diff_value), -1);
    ASSERT_EQ(util_version_compare(nullptr, version2, &diff_value), -1);
    ASSERT_EQ(util_version_compare(version1, version2, nullptr), -1);
    ASSERT_EQ(util_version_compare("1.1.1.1", version2, nullptr), -1);
    ASSERT_EQ(util_version_compare(version1, "a.b.1.1", nullptr), -1);
}

TEST(utils_version, test_util_version_greater_than)
{
    const char *version1 = "0.6.0";
    const char *version2 = "1.0.0";
    bool result = true;

    ASSERT_EQ(util_version_greater_than(version1, version2, &result), 0);
    ASSERT_FALSE(result);
    ASSERT_EQ(util_version_greater_than(version1, version1, &result), 0);
    ASSERT_FALSE(result);
    ASSERT_EQ(util_version_greater_than(version2, version1, &result), 0);
    ASSERT_TRUE(result);
}

TEST(utils_version, test_util_version_greater_than_or_equal_to)
{
    const char *version1 = "0.6.0";
    const char *version2 = "1.0.0";
    bool result = true;

    ASSERT_EQ(util_version_greater_than_or_equal_to(version1, version2, &result), 0);
    ASSERT_FALSE(result);
    ASSERT_EQ(util_version_greater_than_or_equal_to(version1, version1, &result), 0);
    ASSERT_TRUE(result);
    ASSERT_EQ(util_version_greater_than_or_equal_to(version2, version1, &result), 0);
    ASSERT_TRUE(result);
}

