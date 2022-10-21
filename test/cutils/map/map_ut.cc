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
 * Description: map unit test
 * Author: zhangxiaoyu
 * Create: 2022-10-19
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "map.h"

static void ptr_ptr_map_kefree(void *key, void *value)
{
    return;
}

TEST(map_map_ut, test_map_string)
{
    // map[string][bool]
    map_t *map_test = nullptr;
    bool exist = true;

    map_test = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    ASSERT_NE(map_test, nullptr);
    ASSERT_EQ(map_insert(map_test, (void *)"key", &exist), true);

    map_itor *itor = map_itor_new(map_test);
    ASSERT_NE(itor, nullptr);
    ASSERT_EQ(map_itor_first(itor), true);
    ASSERT_EQ(map_itor_last(itor), true);
    ASSERT_EQ(map_itor_prev(itor), false);

    map_itor_free(itor);
    map_clear(map_test);
}

TEST(map_map_ut, test_map_int)
{
    int key = 3;
    int value = 5;
    int *value_ptr = nullptr;
    // map[int][int]
    map_t *map_test = nullptr;

    map_test = map_new(MAP_INT_INT, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    ASSERT_NE(map_test, nullptr);
    ASSERT_EQ(map_insert(map_test, &key, &value), true);

    key = 22;
    value = 33;
    ASSERT_EQ(map_insert(map_test, &key, &value), true);

    value_ptr = (int *)map_search(map_test, &key);
    ASSERT_EQ(*value_ptr, 33);

    key = 44;
    ASSERT_EQ(map_search(map_test, &key), nullptr);

    map_clear(map_test);
}

TEST(map_map_ut, test_map_ptr)
{
    int *key_ptr = new int(3);
    int *value_ptr = new int(5);
    // map[ptr][ptr]
    map_t *map_test = nullptr;

    map_test = map_new(MAP_PTR_PTR, MAP_DEFAULT_CMP_FUNC, ptr_ptr_map_kefree);
    ASSERT_NE(map_test, nullptr);
    ASSERT_EQ(map_insert(map_test, key_ptr, value_ptr), true);
    ASSERT_EQ(map_search(map_test, key_ptr), value_ptr);
    ASSERT_EQ(map_search(map_test, nullptr), nullptr);

    map_clear(map_test);
    delete key_ptr;
    delete value_ptr;
}
