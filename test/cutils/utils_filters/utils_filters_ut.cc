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
 * Description: filters unit test
 * Author: zhongtao
 * Create: 2022-10-17
 */

#include <gtest/gtest.h>
#include "filters.h"
#include "utils.h"

TEST(utils_filters, test_filters)
{
    struct filters_args *filters = filters_args_new();
    ASSERT_NE(filters, nullptr);

    const char *key1_outside = "lable";
    const char *key1_inside = "lable1";
    const char *value1_inside = "1";
    const char *value1_outside = "lable1=1";
    const char *exact_value1_outside = "lable2=2";
    const char *key2_outside = "id";
    const char *value2_outside = "id1=123";
    const char *key3_outside = "patten";
    const char *value3_outside = "^/?[a-zA-Z0-9][a-zA-Z0-9_.-]+$";
    const char *match_patten = "c8da28a6cea7443b648ec70a1c947b6cb920ee0ef3c4a691d4252ff6e1888036";
    const char *unmatch_patten = "#c8da28a6cea7443b648ec70a1c947b6cb920ee0ef3c4a691d4252ff6e1888036";

    //test filters_args_add
    ASSERT_EQ(filters_args_add(filters, key1_outside, value1_outside), true);
    ASSERT_EQ(filters_args_add(filters, key2_outside, value2_outside), true);
    ASSERT_EQ(filters_args_add(filters, key3_outside, value3_outside), true);

    ASSERT_EQ(filters_args_add(nullptr, key1_outside, value1_outside), false);

    //test filters_args_get
    char **value = NULL;
    value = filters_args_get(filters, key2_outside);
    ASSERT_NE(value, nullptr);
    ASSERT_STREQ(*value, value2_outside);

    value = filters_args_get(nullptr, key1_outside);
    ASSERT_EQ(value, nullptr);

    // test filters_args_len
    ASSERT_EQ(filters_args_len(nullptr), 0);
    ASSERT_EQ(filters_args_len(filters), 3);

    //test filters_args_del
    ASSERT_EQ(filters_args_del(filters, key2_outside, value2_outside), true);
    value = filters_args_get(filters, key2_outside);
    ASSERT_EQ(value, nullptr);

    ASSERT_EQ(filters_args_del(nullptr, key1_outside, value1_outside), false);

    //test filters_args_match_kv_list
    map_t *source = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    ASSERT_EQ(map_replace(source, (void *)key1_inside, (void *)value1_inside), true);

    ASSERT_EQ(filters_args_match_kv_list(filters, key1_outside, source), true);
    ASSERT_EQ(filters_args_match_kv_list(filters, key1_outside, nullptr), false);
    ASSERT_EQ(filters_args_match_kv_list(nullptr, key1_outside, source), true);

    //test filters_args_exact_match
    ASSERT_EQ(filters_args_exact_match(filters, key1_outside, value1_outside), true);
    ASSERT_EQ(filters_args_exact_match(filters, key1_outside, exact_value1_outside), false);
    ASSERT_EQ(filters_args_exact_match(nullptr, key1_outside, exact_value1_outside), true);
    ASSERT_EQ(filters_args_exact_match(filters, key1_outside, nullptr), false);

    //test filters_args_match
    ASSERT_EQ(filters_args_match(filters, key3_outside, match_patten), true);
    ASSERT_EQ(filters_args_match(filters, key3_outside, unmatch_patten), false);
    ASSERT_EQ(filters_args_match(nullptr, key3_outside, match_patten), true);
    ASSERT_EQ(filters_args_match(filters, key3_outside, nullptr), false);

    //test filters_args_free
    filters_args_free(nullptr);
    filters_args_free(filters);
}

TEST(utils_filters, test_filters_args_valid_key)
{
    const char *accepted_filters[] = { "id", "label", "name", NULL };
    const char *valid = "name";
    const char *invalid = "description";

    ASSERT_EQ(filters_args_valid_key(accepted_filters, sizeof(accepted_filters) / sizeof(char *), valid), true);
    ASSERT_EQ(filters_args_valid_key(accepted_filters, sizeof(accepted_filters) / sizeof(char *), invalid), false);

    ASSERT_EQ(filters_args_valid_key(accepted_filters, sizeof(accepted_filters) / sizeof(char *), nullptr), false);
    ASSERT_EQ(filters_args_valid_key(nullptr, 3, valid), false);
    ASSERT_EQ(filters_args_valid_key(accepted_filters, 1, valid), false);
    ASSERT_EQ(filters_args_valid_key(accepted_filters, 5, valid), true);

}