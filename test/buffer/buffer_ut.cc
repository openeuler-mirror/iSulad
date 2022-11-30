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
 * Description: buffer unit test
 * Author: chengzeruizhi
 * Create: 2022-11-29
 */

#include <gtest/gtest.h>

#include "buffer.h"

TEST(buffer, test_buffer_alloc)
{
    Buffer *buffer = buffer_alloc(0);
    EXPECT_EQ(buffer, nullptr);

    buffer = buffer_alloc(-1);
    EXPECT_EQ(buffer, nullptr);

    buffer = buffer_alloc(SIZE_MAX + 1);
    EXPECT_EQ(buffer, nullptr);

    buffer = buffer_alloc(10);
    ASSERT_NE(buffer, nullptr);
    EXPECT_EQ(buffer->total_size, 10);
    EXPECT_EQ(buffer->bytes_used, 0);
    EXPECT_NE(buffer->contents, nullptr);
    buffer_free(buffer);
}

TEST(buffer, test_buffer_strlen)
{
    Buffer *buffer = buffer_alloc(0);
    EXPECT_EQ(buffer_strlen(buffer), 0);
    buffer = buffer_alloc(-1);
    EXPECT_EQ(buffer_strlen(buffer), 0);
    buffer = buffer_alloc(SIZE_MAX + 1);
    EXPECT_EQ(buffer_strlen(buffer), 0);
    buffer = buffer_alloc(10);
    ASSERT_NE(buffer, nullptr);
    EXPECT_EQ(buffer_strlen(buffer), 0);
    ASSERT_EQ(buffer_append(buffer, "append", 6), 0);
    EXPECT_EQ(buffer_strlen(buffer), 6);
    buffer_free(buffer);
}

TEST(buffer, test_buffer_free)
{
    Buffer *buffer = nullptr;
    buffer_free(buffer);
    EXPECT_EQ(buffer, nullptr);
}

TEST(buffer, test_buffer_append)
{
    EXPECT_EQ(buffer_append(nullptr, "append", 6), -1);
    Buffer *buffer = buffer_alloc(5);
    EXPECT_EQ(buffer_append(buffer, "buffer needs to grow", 20), 0);
    EXPECT_STREQ(buffer->contents, "buffer needs to grow");
    EXPECT_EQ(buffer->bytes_used, 20);
    EXPECT_EQ(buffer->total_size, 42);
    buffer_free(buffer);

    buffer = buffer_alloc(20);
    EXPECT_EQ(buffer_append(buffer, "first", 5), 0);
    EXPECT_EQ(buffer->bytes_used, 5);
    EXPECT_STREQ(buffer->contents, "first");
    EXPECT_EQ(buffer_append(buffer, "second", 6), 0);
    EXPECT_EQ(buffer->bytes_used, 11);
    EXPECT_EQ(buffer->total_size, 20);
    EXPECT_STREQ(buffer->contents, "firstsecond");
}

TEST(buffer, test_buffer_empty)
{
    Buffer *buffer = buffer_alloc(10);
    buffer_append(buffer, "content", 7);
    buffer_empty(buffer);
    EXPECT_EQ(buffer->total_size, 10);
    EXPECT_EQ(buffer->bytes_used, 0);
}
