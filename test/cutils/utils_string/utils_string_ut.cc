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
 * Description: utils_string unit test
 * Author: tanyifeng
 * Create: 2019-07-08
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "utils_string.h"

extern "C" {
    DECLARE_WRAPPER(util_strdup_s, char *, (const char *str));
    DEFINE_WRAPPER(util_strdup_s, char *, (const char *str), (str));

    DECLARE_WRAPPER(calloc, void *, (size_t nmemb, size_t size));
    DEFINE_WRAPPER(calloc, void *, (size_t nmemb, size_t size), (nmemb, size));
}

TEST(utils_string_ut, test_strings_count)
{
    ASSERT_EQ(util_strings_count("aaaaaaaaaaaaaaaaaaaa", 'a'), 20);
    ASSERT_EQ(util_strings_count("a", 'a'), 1);
    ASSERT_EQ(util_strings_count("", 'a'), 0);
    ASSERT_EQ(util_strings_count(nullptr, 'c'), 0);
}

TEST(utils_string_ut, test_strings_contains_any)
{
    ASSERT_EQ(util_strings_contains_any("1234567890abcdefgh!@", "ijklmnopq#123456789"), true);
    ASSERT_EQ(util_strings_contains_any("1234567890abcdefgh!@", "ijklmnopqrstuvw)(*x&-"), false);
    ASSERT_EQ(util_strings_contains_any("1234567890abcdefgh!@", ""), false);
    ASSERT_EQ(util_strings_contains_any("1234567890abcdefgh!@", nullptr), false);
    ASSERT_EQ(util_strings_contains_any("a", "cedefga123415"), true);
    ASSERT_EQ(util_strings_contains_any("", "ijklmnopq#123456789"), false);
    ASSERT_EQ(util_strings_contains_any(nullptr, "ijklmnopq#123456789"), false);
}

TEST(utils_string_ut, test_strings_to_lower)
{
    char *result = nullptr;

    std::string str = "AB&^%CDE";
    result = util_strings_to_lower(str.c_str());
    ASSERT_STRNE(result, nullptr);
    ASSERT_STREQ("ab&^%cde", result);
    free(result);
    result = nullptr;

    str = "abcdefg12345*()%^#@";
    result = util_strings_to_lower(str.c_str());
    ASSERT_STRNE(result, nullptr);
    ASSERT_STREQ(str.c_str(), result);
    free(result);
    result = nullptr;

    str = "aBcDeFg12345*()%^#@";
    result = util_strings_to_lower(str.c_str());
    ASSERT_STRNE(result, nullptr);
    ASSERT_STREQ("abcdefg12345*()%^#@", result);
    free(result);
    result = nullptr;

    str = "";
    result = util_strings_to_lower(str.c_str());
    ASSERT_STRNE(result, nullptr);
    ASSERT_STREQ(str.c_str(), result);
    free(result);

    result = util_strings_to_lower(nullptr);
    ASSERT_STREQ(result, nullptr);

    MOCK_SET(util_strdup_s, nullptr);
    str = "A";
    result = util_strings_to_lower(str.c_str());
    ASSERT_STREQ(result, nullptr);
    MOCK_CLEAR(util_strdup_s);
}

TEST(utils_string_ut, test_strings_to_upper)
{
    char *result = nullptr;

    std::string str = "AB&^%CDE";
    result = util_strings_to_upper(str.c_str());
    ASSERT_STRNE(result, nullptr);
    ASSERT_STREQ(str.c_str(), result);
    free(result);

    str = "abcdefg12345*()%^#@";
    result = util_strings_to_upper(str.c_str());
    ASSERT_STRNE(result, nullptr);
    ASSERT_STREQ("ABCDEFG12345*()%^#@", result);
    free(result);

    str = "aBcDeFg12345*()%^#@";
    result = util_strings_to_upper(str.c_str());
    ASSERT_STRNE(result, nullptr);
    ASSERT_STREQ("ABCDEFG12345*()%^#@", result);
    free(result);

    str = "";
    result = util_strings_to_upper(str.c_str());
    ASSERT_STRNE(result, nullptr);
    ASSERT_STREQ(str.c_str(), result);
    free(result);

    result = util_strings_to_upper(nullptr);
    ASSERT_STREQ(result, nullptr);

    MOCK_SET(util_strdup_s, nullptr);
    str = "a";
    result = util_strings_to_upper(str.c_str());
    ASSERT_STREQ(result, nullptr);
    MOCK_CLEAR(util_strdup_s);
}

TEST(utils_string_ut, test_strings_in_slice)
{
    const char *array_long[] = { "abcd", "1234", nullptr, "", "&^%abc" };
    size_t array_long_len = sizeof(array_long) / sizeof(array_long[0]);

    const char *array_short[] = { "abcd" };
    size_t array_short_len = sizeof(array_short) / sizeof(array_short[0]);

    ASSERT_TRUE(util_strings_in_slice(array_long, array_long_len, ""));
    ASSERT_FALSE(util_strings_in_slice(array_long, array_long_len, "abc"));
    ASSERT_FALSE(util_strings_in_slice(array_long, array_long_len, nullptr));
    ASSERT_TRUE(util_strings_in_slice(array_short, array_short_len, "abcd"));
    ASSERT_FALSE(util_strings_in_slice(array_short, array_short_len, "bcd"));
    ASSERT_FALSE(util_strings_in_slice(array_short, array_short_len, nullptr));
    ASSERT_FALSE(util_strings_in_slice(nullptr, 0, "abcd"));
    ASSERT_FALSE(util_strings_in_slice(nullptr, 0, nullptr));
}

TEST(utils_string_ut, test_util_parse_byte_size_string)
{
    int64_t converted = 0;
    int ret;

    ret = util_parse_byte_size_string("10.9876B", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 10);

    ret = util_parse_byte_size_string("2048.965kI", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 2098140);

    ret = util_parse_byte_size_string("1.1GiB", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 1181116006);

    ret = util_parse_byte_size_string("2.0tI", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 2199023255552);

    ret = util_parse_byte_size_string("1024mB", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 1073741824);

    ret = util_parse_byte_size_string("10.12a3PIb", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("1234.0a9", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("-10.123", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("-10.0B", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("-10.0GiB", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("-10kI", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("-10tI", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("-10Pib", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("-10.12a3mB", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("0.12345mB", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 129446);

    ret = util_parse_byte_size_string("0.9876543210123456789tI", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 1085937410176);

    ret = util_parse_byte_size_string("0.0kI", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 0);

    ret = util_parse_byte_size_string("0.0Pib", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 0);

    ret = util_parse_byte_size_string("0", &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 0);

    ret = util_parse_byte_size_string("0.123aB", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("0.123aGiB", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("9223372036854775808.123B", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("9007199254740992.0kI", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("8796093022208.0mB", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("8589934592GiB", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("8192PIb", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("8388608.1abtI", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("9223372036854775808.1a", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("123a456.123mB", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("6a1.123Pib", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("12a.0GiB", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("a1230.0", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("1&3B", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("a1tI", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("1a.a1kI", &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string(nullptr, &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("1", nullptr);
    ASSERT_NE(ret, 0);

    ret = util_parse_byte_size_string("", &converted);
    ASSERT_NE(ret, 0);

    MOCK_SET(util_strdup_s, nullptr);
    ret = util_parse_byte_size_string("1", &converted);
    ASSERT_NE(ret, 0);
    MOCK_CLEAR(util_strdup_s);
}

TEST(utils_string_ut, test_util_string_split_multi)
{
    char **result = nullptr;

    result = util_string_split_multi("abcd,,,1234999999999", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], "");
    free(result[1]);
    ASSERT_STREQ(result[2], "");
    free(result[2]);
    ASSERT_STREQ(result[3], "1234999999999");
    free(result[3]);
    ASSERT_STREQ(result[4], nullptr);
    free(result);

    result = util_string_split_multi("abcd,1234,*&^(,defgz", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], "1234");
    free(result[1]);
    ASSERT_STREQ(result[2], "*&^(");
    free(result[2]);
    ASSERT_STREQ(result[3], "defgz");
    free(result[3]);
    ASSERT_STREQ(result[4], nullptr);
    free(result);

    result = util_string_split_multi(",abcd,12340000000000", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "");
    free(result[0]);
    ASSERT_STREQ(result[1], "abcd");
    free(result[1]);
    ASSERT_STREQ(result[2], "12340000000000");
    free(result[2]);
    ASSERT_STREQ(result[3], nullptr);
    free(result);

    result = util_string_split_multi("abcd,12340000000000,", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], "12340000000000");
    free(result[1]);
    ASSERT_STREQ(result[2], "");
    free(result[2]);
    ASSERT_STREQ(result[3], nullptr);
    free(result);

    result = util_string_split_multi("abcd,1234,", 'x');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd,1234,");
    free(result[0]);
    ASSERT_STREQ(result[1], nullptr);
    free(result);

    result = util_string_split_multi(",", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "");
    free(result[0]);
    ASSERT_STREQ(result[1], "");
    free(result[1]);
    ASSERT_STREQ(result[2], nullptr);
    free(result);

    result = util_string_split_multi("", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "");
    free(result[0]);
    ASSERT_STREQ(result[1], nullptr);
    free(result);

    result = util_string_split_multi(nullptr, ',');
    ASSERT_EQ(result, nullptr);

    MOCK_SET(calloc, nullptr);
    result = util_string_split_multi("abcd,12340000000000,", ',');
    ASSERT_EQ(result, nullptr);
    MOCK_CLEAR(calloc);
}

TEST(utils_string_ut, test_util_string_split)
{
    char **result = nullptr;

    result = util_string_split("abcd,,,1234999999999", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], "1234999999999");
    free(result[1]);
    ASSERT_STREQ(result[2], nullptr);
    free(result);

    result = util_string_split("abcd,1234,*&^(,defgz", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], "1234");
    free(result[1]);
    ASSERT_STREQ(result[2], "*&^(");
    free(result[2]);
    ASSERT_STREQ(result[3], "defgz");
    free(result[3]);
    ASSERT_STREQ(result[4], nullptr);
    free(result);

    result = util_string_split(",abcd,12340000000000", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], "12340000000000");
    free(result[1]);
    ASSERT_STREQ(result[2], nullptr);
    free(result);

    result = util_string_split("abcd,12340000000000,", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], "12340000000000");
    free(result[1]);
    ASSERT_STREQ(result[2], nullptr);
    free(result);

    result = util_string_split("abcd,1234,", 'x');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd,1234,");
    free(result[0]);
    ASSERT_STREQ(result[1], nullptr);
    free(result);

    result = util_string_split(",", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "");
    free(result[0]);
    ASSERT_STREQ(result[1], nullptr);
    free(result);

    result = util_string_split("", ',');
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "");
    free(result[0]);
    ASSERT_STREQ(result[1], nullptr);
    free(result);

    result = util_string_split(nullptr, ',');
    ASSERT_EQ(result, nullptr);

    MOCK_SET(calloc, nullptr);
    result = util_string_split("abcd,12340000000000,", ',');
    ASSERT_EQ(result, nullptr);
    MOCK_CLEAR(calloc);
}

TEST(utils_string_ut, test_str_skip_str)
{
    const char *str = "abcdefghij1234567890";
    const char *substr = "abcdefgh";
    const char *result = nullptr;

    result = util_str_skip_str(str, substr);
    ASSERT_STREQ(result, "ij1234567890");

    result = util_str_skip_str(str, "habc");
    ASSERT_STREQ(result, nullptr);

    result = util_str_skip_str(str, "");
    ASSERT_STREQ(result, str);

    result = util_str_skip_str(str, nullptr);
    ASSERT_STREQ(result, nullptr);

    result = util_str_skip_str("a", "a");
    ASSERT_STREQ(result, "");

    result = util_str_skip_str("", "");
    ASSERT_STREQ(result, "");

    result = util_str_skip_str(nullptr, "");
    ASSERT_STREQ(result, nullptr);
}

TEST(utils_string_ut, test_util_string_delchar)
{
    char *result = nullptr;

    result = util_string_delchar("aaaaaaaaaaaaaaaaaaaa", 'a');
    ASSERT_STREQ(result, "");
    free(result);

    result = util_string_delchar("1234567890abc*&^ghij", 'a');
    ASSERT_STREQ(result, "1234567890bc*&^ghij");
    free(result);

    result = util_string_delchar("1234567890abc*&^ghij", 'z');
    ASSERT_STREQ(result, "1234567890abc*&^ghij");
    free(result);

    result = util_string_delchar(nullptr, 'a');
    ASSERT_STREQ(result, nullptr);

    MOCK_SET(util_strdup_s, nullptr);
    result = util_string_delchar("a", 'a');
    ASSERT_STREQ(result, nullptr);
    MOCK_CLEAR(util_strdup_s);
}

TEST(utils_string_ut, test_util_trim_newline)
{
    char s_all[] = { '\n', '\n', '\n', '\n', '\0' };
    char s_tail[] = { '\n', 'a', '\n', 'b', '\n', '\0' };
    char s_not_n[] = { 'a', '\n', 'b', 'c', '\0' };
    char s_empty[] = { '\0' };
    char *s_nullptr = nullptr;

    util_trim_newline(s_all);
    ASSERT_STREQ(s_all, "");

    util_trim_newline(s_tail);
    ASSERT_STREQ(s_tail, "\na\nb");

    util_trim_newline(s_not_n);
    ASSERT_STREQ(s_not_n, "a\nbc");

    util_trim_newline(s_empty);
    ASSERT_STREQ(s_empty, "");

    util_trim_newline(s_nullptr);
    ASSERT_STREQ(s_nullptr, nullptr);
}

TEST(utils_string_ut, test_util_trim_space)
{
    char s_all[] = { '\f', '\n', '\r', '\t', '\v', ' ', '\0' };
    char s_head[] = { '\f', '\n', '\r', 'a', 'b', 'c', '\0' };
    char s_tail[] = { 'a', 'b', 'c', '\t', '\v', ' ', '\0' };
    char s_head_tail[] = { '\f', 'a', 'b', 'c', '\v', ' ', '\0' };
    char s_mid[] = { 'a', 'b', '\r', '\t', '\v', 'c', '\0' };
    char s_not_space[] = { 'a', 'a', 'b', 'b', 'c', 'c', '\0' };
    char s_empty[] = { '\0' };
    char *s_nullptr = nullptr;
    char *result = nullptr;

    result = util_trim_space(s_all);
    ASSERT_STREQ(result, "");

    result = util_trim_space(s_head);
    ASSERT_STREQ(result, "abc");

    result = util_trim_space(s_tail);
    ASSERT_STREQ(result, "abc");

    result = util_trim_space(s_head_tail);
    ASSERT_STREQ(result, "abc");

    result = util_trim_space(s_mid);
    ASSERT_STREQ(result, "ab\r\t\vc");

    result = util_trim_space(s_not_space);
    ASSERT_STREQ(result, "aabbcc");

    result = util_trim_space(s_empty);
    ASSERT_STREQ(result, "");

    result = util_trim_space(s_nullptr);
    ASSERT_STREQ(result, nullptr);
}

TEST(utils_string_ut, test_util_trim_quotation)
{
    char s_all[] = { '"', '"', '"', '\n', '"', '\0' };
    char s_head[] = { '"', '"', 'a', 'b', 'c', '\0' };
    char s_tail_n[] = { 'a', 'b', 'c', '\n', '\n', '\0' };
    char s_tail_quo[] = { 'a', 'b', 'c', '"', '"', '\0' };
    char s_head_tail[] = { '"', '"', 'a', '\n', '"', '\0' };
    char s_mid[] = { 'a', 'b', '"', '\n', 'c', '\0' };
    char s_not_space[] = { 'a', 'b', 'c', 'd', 'e', '\0' };
    char s_empty[] = { '\0' };
    char *s_nullptr = nullptr;
    char *result = nullptr;

    result = util_trim_quotation(s_all);
    ASSERT_STREQ(result, "");

    result = util_trim_quotation(s_head);
    ASSERT_STREQ(result, "abc");

    result = util_trim_quotation(s_tail_n);
    ASSERT_STREQ(result, "abc");

    result = util_trim_quotation(s_tail_quo);
    ASSERT_STREQ(result, "abc");

    result = util_trim_quotation(s_head_tail);
    ASSERT_STREQ(result, "a");

    result = util_trim_quotation(s_mid);
    ASSERT_STREQ(result, "ab\"\nc");

    result = util_trim_quotation(s_not_space);
    ASSERT_STREQ(result, "abcde");

    result = util_trim_quotation(s_empty);
    ASSERT_STREQ(result, "");

    result = util_trim_quotation(s_nullptr);
    ASSERT_STREQ(result, nullptr);
}

TEST(utils_string_ut, test_str_array_dup)
{
    const char *array_long[] = { "abcd", "1234", nullptr, "", "&^%abc" };
    size_t array_long_len = sizeof(array_long) / sizeof(array_long[0]);

    const char *array_short[] = { "abcd" };
    size_t array_short_len = sizeof(array_short) / sizeof(array_short[0]);

    char **result = nullptr;

    result = util_str_array_dup(array_long, array_long_len);
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], "1234");
    free(result[1]);
    ASSERT_STREQ(result[2], nullptr);
    ASSERT_STREQ(result[3], "");
    free(result[3]);
    ASSERT_STREQ(result[4], "&^%abc");
    free(result[4]);
    ASSERT_STREQ(result[5], nullptr);
    free(result);

    result = util_str_array_dup(array_short, array_short_len);
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], nullptr);
    free(result);

    result = util_str_array_dup(nullptr, 0);
    ASSERT_EQ(result, nullptr);
}

TEST(utils_string_ut, test_util_string_join)
{
    const char *array_long[] = { "abcd", "1234", "5678", "", "&^%abc" };
    size_t array_long_len = sizeof(array_long) / sizeof(array_long[0]);

    const char *array_short[] = { "abcd" };
    size_t array_short_len = sizeof(array_short) / sizeof(array_short[0]);

    const char *array_nullptr[] = { nullptr };
    size_t array_nullptr_len = sizeof(array_nullptr) / sizeof(array_nullptr[0]);

    char *result = nullptr;

    result = util_string_join("   ", array_long, array_long_len);
    ASSERT_STREQ(result, "abcd   1234   5678      &^%abc");
    free(result);

    result = util_string_join("   ", array_short, array_short_len);
    ASSERT_STREQ(result, "abcd");
    free(result);

    result = util_string_join("   ", array_nullptr, array_nullptr_len);
    ASSERT_EQ(result, nullptr);

    result = util_string_join("   ", nullptr, 0);
    ASSERT_EQ(result, nullptr);

    result = util_string_join("", array_long, array_long_len);
    ASSERT_STREQ(result, "abcd12345678&^%abc");
    free(result);

    result = util_string_join(nullptr, array_long, array_long_len);
    ASSERT_STREQ(result, nullptr);
}

TEST(utils_string_ut, test_util_string_append)
{
    char *result = nullptr;

    result = util_string_append("abc", "123");
    ASSERT_STREQ(result, "123abc");
    free(result);

    result = util_string_append("abc", "");
    ASSERT_STREQ(result, "abc");
    free(result);

    result = util_string_append("abc", nullptr);
    ASSERT_STREQ(result, "abc");
    free(result);

    result = util_string_append("", "123");
    ASSERT_STREQ(result, "123");
    free(result);

    result = util_string_append("", "");
    ASSERT_STREQ(result, "");
    free(result);

    result = util_string_append("", nullptr);
    ASSERT_STREQ(result, "");
    free(result);

    result = util_string_append(nullptr, "123");
    ASSERT_STREQ(result, "123");
    free(result);

    result = util_string_append(nullptr, "");
    ASSERT_STREQ(result, "");
    free(result);

    result = util_string_append(nullptr, nullptr);
    ASSERT_STREQ(result, nullptr);

    MOCK_SET(calloc, nullptr);
    result = util_string_append("abc", "123");
    ASSERT_STREQ(result, nullptr);
    MOCK_CLEAR(calloc);
}

TEST(utils_string_ut, test_dup_array_of_strings)
{
    const char *array_long[] = { "abcd", "1234", nullptr, "", "&^%abc" };
    size_t array_long_len = sizeof(array_long) / sizeof(array_long[0]);

    const char *array_short[] = { "abcd" };
    size_t array_short_len = sizeof(array_short) / sizeof(array_short[0]);

    char **result = nullptr;
    size_t result_len = 0;
    int ret;

    ret = util_dup_array_of_strings(array_long, array_long_len, &result, &result_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(array_long_len, result_len);
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    ASSERT_STREQ(result[1], "1234");
    free(result[1]);
    ASSERT_STREQ(result[2], nullptr);
    ASSERT_STREQ(result[3], "");
    free(result[3]);
    ASSERT_STREQ(result[4], "&^%abc");
    free(result[4]);
    free(result);
    result = nullptr;

    ret = util_dup_array_of_strings(array_long, array_long_len, &result, nullptr);
    ASSERT_NE(ret, 0);

    ret = util_dup_array_of_strings(array_long, array_long_len, nullptr, &result_len);
    ASSERT_NE(ret, 0);

    ret = util_dup_array_of_strings(array_short, array_short_len, &result, &result_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(array_short_len, result_len);
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "abcd");
    free(result[0]);
    free(result);
    result = nullptr;

    ret = util_dup_array_of_strings(nullptr, 0, &result, &result_len);
    ASSERT_EQ(ret, 0);

    MOCK_SET(calloc, nullptr);
    ret = util_dup_array_of_strings(array_long, array_long_len, &result, &result_len);
    ASSERT_NE(ret, 0);
    MOCK_CLEAR(calloc);
}

TEST(utils_string_ut, test_parse_percent_string)
{
    long converted = 0;
    int ret = 0;
    const char *correct1 = "10%";
    const char *correct2 = "0%";
    const char *correct3 = "100%";
    const char *correct4 = "99%";
    const char *wrong1 = "50";
    const char *wrong2 = "-10%";
    const char *wrong3 = "101%";
    const char *wrong4 = "a10%";
    const char *wrong5 = "10%k";
    const char *wrong6 = "1x0%";

    ret = util_parse_percent_string(correct1, &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 10);

    ret = util_parse_percent_string(correct2, &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 0);

    ret = util_parse_percent_string(correct3, &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 100);

    ret = util_parse_percent_string(correct4, &converted);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(converted, 99);

    ret = util_parse_percent_string(wrong1, &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_percent_string(wrong2, &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_percent_string(wrong3, &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_percent_string(wrong4, &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_percent_string(wrong5, &converted);
    ASSERT_NE(ret, 0);

    ret = util_parse_percent_string(wrong6, &converted);
    ASSERT_NE(ret, 0);
}
