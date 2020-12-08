/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: utils_convert unit test
 * Author: tanyifeng
 * Create: 2019-07-08
 */

#include <stdlib.h>
#include <stdio.h>
#include <climits>
#include <gtest/gtest.h>
#include "mock.h"
#include "utils_convert.h"

TEST(utils_convert, test_util_safe_u16)
{
    int ret;
    uint16_t converted;
    ret = util_safe_u16("255", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 255);

    ret = util_safe_u16("255", nullptr);
    ASSERT_NE(ret, 0);

    ret = util_safe_u16("-1", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_u16("0", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 0);

    ret = util_safe_u16("1.23", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_u16("1x", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_u16(std::to_string((long long)UINT16_MAX + 1).c_str(), &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_u16("nullptr", &converted);
    ASSERT_NE(ret, 0);
}

TEST(utils_convert, test_util_safe_int)
{
    int ret;
    int converted;
    ret = util_safe_int("123456", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 123456);

    ret = util_safe_int("123456", nullptr);
    ASSERT_NE(ret, 0);

    ret = util_safe_int("-123456", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, -123456);

    ret = util_safe_int("0", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 0);

    ret = util_safe_int("1.23", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_int("1x", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_int(std::to_string((long long)INT_MIN - 1).c_str(), &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_int(std::to_string((long long)INT_MAX + 1).c_str(), &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_int("nullptr", &converted);
    ASSERT_NE(ret, 0);
}

TEST(utils_convert, test_util_safe_uint)
{
    int ret;
    unsigned int converted;
    ret = util_safe_uint("123456", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 123456);

    ret = util_safe_uint("123456", nullptr);
    ASSERT_NE(ret, 0);

    ret = util_safe_uint("-123456", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_uint("0", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 0);

    ret = util_safe_uint("1.23", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_uint("1x", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_uint(std::to_string((long long)UINT_MAX + 1).c_str(), &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_uint("nullptr", &converted);
    ASSERT_NE(ret, 0);
}

TEST(utils_convert, test_util_safe_llong)
{
    int ret;
    long long converted;
    ret = util_safe_llong("123456", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 123456);

    ret = util_safe_llong("123456", nullptr);
    ASSERT_NE(ret, 0);

    ret = util_safe_llong("-123456", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, -123456);

    ret = util_safe_llong("0", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 0);

    ret = util_safe_llong("1.23", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_llong("1x", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_llong("-9223372036854775809", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_llong("9223372036854775808", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_llong("nullptr", &converted);
    ASSERT_NE(ret, 0);
}

TEST(utils_convert, test_util_safe_strtod)
{
    int ret;
    double converted;
    ret = util_safe_strtod("123456", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_DOUBLE_EQ(converted, 123456);

    ret = util_safe_strtod("123456", nullptr);
    ASSERT_NE(ret, 0);

    ret = util_safe_strtod("-123456", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_DOUBLE_EQ(converted, -123456);

    ret = util_safe_strtod("0", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_DOUBLE_EQ(converted, 0);

    ret = util_safe_strtod("123.456", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_DOUBLE_EQ(converted, 123.456);

    ret = util_safe_strtod("1x", &converted);
    ASSERT_NE(ret, 0);

    ret = util_safe_strtod("nullptr", &converted);
    ASSERT_NE(ret, 0);
}

TEST(utils_convert, test_util_str_to_bool)
{
    int ret;
    bool converted = false;
    ret = util_str_to_bool("1", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(converted);

    ret = util_str_to_bool("1", nullptr);
    ASSERT_NE(ret, 0);

    ret = util_str_to_bool("t", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(converted);

    ret = util_str_to_bool("T", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(converted);

    ret = util_str_to_bool("true", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(converted);

    ret = util_str_to_bool("True", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(converted);

    ret = util_str_to_bool("0", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE(converted);

    ret = util_str_to_bool("f", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE(converted);

    ret = util_str_to_bool("F", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE(converted);

    ret = util_str_to_bool("false", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE(converted);

    ret = util_str_to_bool("FALSE", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE(converted);

    ret = util_str_to_bool("False", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE(converted);

    ret = util_str_to_bool("x", &converted);
    ASSERT_NE(ret, 0);

    ret = util_str_to_bool("nullptr", &converted);
    ASSERT_NE(ret, 0);
}
