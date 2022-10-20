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

TEST(map_map_ut, test_map)
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
