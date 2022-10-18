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
 * Author: zhongtao
 * Create: 2022-10-18
 * Description: utils regex unit test
 *******************************************************************************/

#include <gtest/gtest.h>
#include "utils_regex.h"

TEST(utils_regex, test_util_reg_match)
{
    const char *pattern = "^[a-f0-9]{64}$";
    const char *valid = "c8da28a6cea7443b648ec70a1c947b6cb920ee0ef3c4a691d4252ff6e1888036";
    const char *invalid = "g8da28a6cea7443b648ec70a1c947b6cb920ee0ef3c4a691d4252ff6e1888036";

    ASSERT_EQ(util_reg_match(pattern, valid), 0);
    ASSERT_EQ(util_reg_match(pattern, invalid), 1);

    ASSERT_EQ(util_reg_match(pattern, nullptr), -1);
    ASSERT_EQ(util_reg_match(nullptr, pattern), -1);
}

TEST(utils_regex, test_util_wildcard_to_regex)
{
    std::string wildcard = "*hello?";
    char *value = NULL;

    ASSERT_EQ(util_wildcard_to_regex(wildcard.c_str(), &value), 0);
    ASSERT_STREQ(value, "^.*hello.$");

    wildcard = "file{1,2,3}";
    ASSERT_EQ(util_wildcard_to_regex(wildcard.c_str(), &value), 0);
    ASSERT_STREQ(value, "^file\\{1,2,3\\}$");

    ASSERT_EQ(util_wildcard_to_regex(nullptr, &value), -1);
    ASSERT_EQ(util_wildcard_to_regex(wildcard.c_str(), nullptr), -1);
}
