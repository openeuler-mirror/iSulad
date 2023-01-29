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
 * Description: client_show_format unit test
 * Author: zhongtao
 * Create: 2022-12-05
 */

#include <gtest/gtest.h>
#include "client_show_format.h"
#include "utils.h"

TEST(client_show_format, test_format_filters_field_check)
{
    const char *pattern = "\\{\\{\\s*\\.\\w+\\s*\\}\\}";
    const char *valid = "{{.State}}";
    const char *invalid1 = "{{State}}";
    const char *invalid2 = "23dffg@34";
    const char *invalid3 = "{abc}";
    const char *invalid4 = "{abc{xx}}";
    const char *invalid5 = "{x{y}x}";
    ASSERT_EQ(format_filters_field_check(valid, pattern), 0);

    ASSERT_EQ(format_filters_field_check(invalid1, pattern), -1);
    ASSERT_EQ(format_filters_field_check(invalid2, pattern), -1);
    ASSERT_EQ(format_filters_field_check(invalid3, pattern), -1);
    ASSERT_EQ(format_filters_field_check(invalid4, pattern), -1);
    ASSERT_EQ(format_filters_field_check(invalid5, pattern), -1);

    ASSERT_EQ(format_filters_field_check(nullptr, pattern), -1);
    ASSERT_EQ(format_filters_field_check(valid, nullptr), -1);
}

TEST(client_show_format, test_valid_format_filters_field)
{
    const char *valid = "State";
    const char *invalid = "Create";
    const char *support_field[] = {"State", "Name", "Id", "Image"};
    size_t len = sizeof(support_field) / sizeof(char *);
    ASSERT_EQ(valid_format_filters_field(valid, support_field, len), true);

    ASSERT_EQ(valid_format_filters_field(invalid, support_field, len), false);
    ASSERT_EQ(valid_format_filters_field(valid, nullptr, len), false);
    ASSERT_EQ(valid_format_filters_field(nullptr, support_field, len), false);
}

TEST(client_show_format, test_append_format_filters_field)
{
    struct format_filters *format = (struct format_filters *)util_common_calloc_s(sizeof(struct format_filters));
    ASSERT_NE(format, nullptr);
    ASSERT_EQ(format->field_len, 0);

    struct filters_field *field = (struct filters_field *)util_common_calloc_s(sizeof(struct filters_field));
    field->name = util_strdup_s("test");
    field->is_field = true;

    ASSERT_EQ(append_format_filters_field(format, field), 0);
    ASSERT_EQ(format->field_len, 1);
    ASSERT_STREQ(format->fields[0]->name, "test");
    ASSERT_EQ(format->fields[0]->is_field, true);

    ASSERT_EQ(append_format_filters_field(nullptr, field), -1);
    ASSERT_EQ(append_format_filters_field(format, nullptr), -1);

    free_format_filters(format);
}

TEST(client_show_format, test_get_format_filters_field)
{
    const char *format_str = "table {{.ID}}:{{.Image}}";
    const char *format_str1_invalid = ".Image";
    const char *format_str2_invalid = "{ID} {Image}";
    const char *format_str3_invalid = "ID Image";
    const char *format_str4_invalid = "ID:Image";
    const char *support_field[] = {"ID", "Name", "Id", "Image"};
    size_t len = sizeof(support_field) / sizeof(char *);

    struct format_filters *format = (struct format_filters *)util_common_calloc_s(sizeof(struct format_filters));
    ASSERT_NE(format, nullptr);
    ASSERT_EQ(format->field_len, 0);

    ASSERT_EQ(get_format_filters_field(format_str, format, support_field, len, true), 0);
    ASSERT_EQ(format->field_len, 4);
    ASSERT_STREQ(format->fields[0]->name, "table");
    ASSERT_EQ(format->fields[0]->is_field, true);
    ASSERT_STREQ(format->fields[1]->name, "ID");
    ASSERT_EQ(format->fields[1]->is_field, true);
    ASSERT_STREQ(format->fields[2]->name, ":");
    ASSERT_EQ(format->fields[2]->is_field, false);
    ASSERT_STREQ(format->fields[3]->name, "Image");
    ASSERT_EQ(format->fields[3]->is_field, true);

    free_format_filters(format);
    format = (struct format_filters *)util_common_calloc_s(sizeof(struct format_filters));
    ASSERT_NE(format, nullptr);
    ASSERT_EQ(format->field_len, 0);

    ASSERT_EQ(get_format_filters_field(format_str, format, support_field, len, false), 0);
    ASSERT_EQ(format->field_len, 3);
    ASSERT_STREQ(format->fields[0]->name, "table");
    ASSERT_EQ(format->fields[0]->is_field, true);
    ASSERT_STREQ(format->fields[1]->name, "ID");
    ASSERT_EQ(format->fields[1]->is_field, true);
    ASSERT_STREQ(format->fields[2]->name, "Image");
    ASSERT_EQ(format->fields[2]->is_field, true);

    free_format_filters(format);
    format = (struct format_filters *)util_common_calloc_s(sizeof(struct format_filters));
    ASSERT_NE(format, nullptr);
    ASSERT_EQ(format->field_len, 0);

    ASSERT_EQ(get_format_filters_field(format_str1_invalid, format, support_field, len, false), 0);
    ASSERT_EQ(format->field_len, 0);
    ASSERT_EQ(get_format_filters_field(format_str2_invalid, format, support_field, len, false), 0);
    ASSERT_EQ(format->field_len, 0);
    ASSERT_EQ(get_format_filters_field(format_str3_invalid, format, support_field, len, false), 0);
    ASSERT_EQ(format->field_len, 0);
    ASSERT_EQ(get_format_filters_field(format_str4_invalid, format, support_field, len, false), 0);
    ASSERT_EQ(format->field_len, 0);

    ASSERT_EQ(get_format_filters_field(format_str, format, nullptr, len, false), -1);
    ASSERT_EQ(get_format_filters_field(nullptr, format, support_field, len, false), -1);
    ASSERT_EQ(get_format_filters_field(format_str, nullptr, support_field, len, false), -1);
    ASSERT_EQ(get_format_filters_field(format_str, format, nullptr, len, false), -1);
}