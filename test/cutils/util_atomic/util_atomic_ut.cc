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
 * Description: util_atomic unit test
 * Author: zhangxiaoyu
 * Create: 2022-10-15
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "util_atomic.h"

TEST(utils_atomic_ut, test_atomic_inc_dec)
{
    uint64_t atomic = 0;
    uint64_t atomic_image = 0;

    atomic_int_set(&atomic, 10);
    ASSERT_EQ(atomic_int_get(&atomic), 10);
    ASSERT_EQ(atomic_int_inc(&atomic), 11);
    ASSERT_EQ(atomic_int_dec_test(&atomic), false);

    atomic_int_set_image(&atomic_image, 1);
    ASSERT_EQ(atomic_int_inc_image(&atomic_image), 2);
    ASSERT_EQ(atomic_int_dec_test_image(&atomic_image), false);
    ASSERT_EQ(atomic_int_dec_test_image(&atomic_image), true);
}

TEST(utils_atomic_ut, test_atomic_calculate)
{
    uint64_t atomic = 0;

    ASSERT_EQ(atomic_int_compare_exchange(&atomic, 1, 2), false);


    ASSERT_EQ(atomic_int_compare_exchange(&atomic, 0, 2), true);
    // atomic = 2
    ASSERT_EQ(atomic_int_add(&atomic, 3), 2);
    // atomic = 5
    ASSERT_EQ(atomic_int_and(&atomic, 4), 5);
    // atomic = 4
    ASSERT_EQ(atomic_int_or(&atomic, 8), 4);
    // atomic = 12
    ASSERT_EQ(atomic_int_xor(&atomic, 3), 12);
    // atomic = 15
    ASSERT_EQ(atomic_int_get(&atomic), 15);
}
