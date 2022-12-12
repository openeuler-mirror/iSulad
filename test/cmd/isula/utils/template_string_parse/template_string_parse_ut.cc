/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: template_string_parse unit test
 * Author: zhongtao
 * Create: 2022-12-05
 */

#include <gtest/gtest.h>
#include "template_string_parse.h"

TEST(template_string_parse, test_parse_single_template_string)
{
    const char *json_str = "{{json .State}";
    const char *temp_str = "{{.ID}}";
    const char *invalid_str = ".Invalid";
    
    ASSERT_STREQ(parse_single_template_string(json_str),"State");
    ASSERT_STREQ(parse_single_template_string(temp_str),"ID");

    ASSERT_EQ(parse_single_template_string(nullptr), nullptr);
    ASSERT_STREQ(parse_single_template_string(invalid_str), nullptr);
}