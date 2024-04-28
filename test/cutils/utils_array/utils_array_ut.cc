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
 * Description: utils_array unit test
 * Author: tanyifeng
 * Create: 2019-09-24
 */

#include <stdlib.h>
#include <stdio.h>
#include <climits>
#include <gtest/gtest.h>
#include "mock.h"
#include "utils_array.h"
#include "utils.h"

extern "C" {
    DECLARE_WRAPPER(calloc, void *, (size_t nmemb, size_t size));
    DEFINE_WRAPPER(calloc, void *, (size_t nmemb, size_t size), (nmemb, size));
}

TEST(utils_array, test_util_array_len)
{
    const char *array_long[] = { "abcd", "1234", "a1b", nullptr };

    ASSERT_EQ(util_array_len(nullptr), 0);

    ASSERT_EQ(util_array_len(array_long), 3);
}

TEST(utils_array, test_util_free_array)
{
    char **array = nullptr;

    array = (char **)util_common_calloc_s(4 * sizeof(char *));
    ASSERT_NE(array, nullptr);
    array[0] = util_strdup_s("test1");
    array[1] = util_strdup_s("test2");
    array[2] = util_strdup_s("test3");
    array[3] = nullptr;

    util_free_array(nullptr);
    util_free_array(array);
}

TEST(utils_array, test_util_copy_array_by_len)
{
    char **array = nullptr;
    char **array_copy = nullptr;
    size_t len = 3;

    array = (char **)util_common_calloc_s(4 * sizeof(char *));
    ASSERT_NE(array, nullptr);
    array[0] = util_strdup_s("test1");
    array[1] = util_strdup_s("test2");
    array[2] = util_strdup_s("test3");

    array_copy = util_copy_array_by_len(array, len);
    ASSERT_NE(array_copy, nullptr);
    for (size_t i = 0; i < len; i++) {
        ASSERT_EQ(strcmp(array_copy[i], array[i]), 0);
        free(array[i]);
        free(array_copy[i]);
    }

    ASSERT_EQ(util_copy_array_by_len(array, 0), nullptr);
    ASSERT_EQ(util_copy_array_by_len(nullptr, len), nullptr);

    free(array);
    free(array_copy);
}

TEST(utils_array, test_util_grow_array)
{
    char **array = nullptr;
    size_t capacity = 0;
    int ret;

    capacity = 1;
    array = (char **)util_common_calloc_s(sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(&array, &capacity, 1, 1);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(array, nullptr);
    ASSERT_EQ(array[0], nullptr);
    ASSERT_EQ(array[1], nullptr);
    ASSERT_EQ(capacity, 2);
    util_free_array(array);
    array = nullptr;
    capacity = 0;

    capacity = 1;
    array = (char **)util_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(&array, &capacity, 1, 2);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(array, nullptr);
    ASSERT_EQ(array[0], nullptr);
    ASSERT_EQ(array[1], nullptr);
    ASSERT_EQ(array[2], nullptr);
    ASSERT_EQ(capacity, 3);
    util_free_array(array);
    array = nullptr;
    capacity = 0;

    capacity = 1;
    array = (char **)util_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(&array, &capacity, 1, 4);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(array, nullptr);
    ASSERT_EQ(array[0], nullptr);
    ASSERT_EQ(array[1], nullptr);
    ASSERT_EQ(array[2], nullptr);
    ASSERT_EQ(array[3], nullptr);
    ASSERT_EQ(array[4], nullptr);
    ASSERT_EQ(capacity, 5);
    util_free_array(array);
    array = nullptr;
    capacity = 0;

    capacity = 1;
    array = (char **)util_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(&array, &capacity, 1, 0);
    ASSERT_NE(ret, 0);
    util_free_array(array);
    array = nullptr;
    capacity = 0;

    capacity = 1;
    array = (char **)util_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(&array, &capacity, 4, 1);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(array, nullptr);
    ASSERT_EQ(array[0], nullptr);
    ASSERT_EQ(array[1], nullptr);
    ASSERT_EQ(array[2], nullptr);
    ASSERT_EQ(array[3], nullptr);
    ASSERT_EQ(array[4], nullptr);
    ASSERT_EQ(capacity, 5);
    util_free_array(array);
    array = nullptr;
    capacity = 0;

    capacity = 1;
    array = (char **)util_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(&array, &capacity, 0, 1);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(array, nullptr);
    ASSERT_EQ(array[0], nullptr);
    ASSERT_EQ(capacity, 1);
    util_free_array(array);
    array = nullptr;
    capacity = 0;

    capacity = 1;
    array = (char **)util_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(&array, nullptr, 1, 1);
    ASSERT_NE(ret, 0);
    util_free_array(array);
    array = nullptr;
    capacity = 0;

    capacity = 1;
    array = (char **)util_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(nullptr, &capacity, 1, 1);
    ASSERT_NE(ret, 0);
    util_free_array(array);
    array = nullptr;
    capacity = 0;
}

TEST(utils_array, test_util_array_append)
{
    char **array = nullptr;
    char **array_three = nullptr;
    int ret;

    ret = util_array_append(&array, "1234567890");
    ASSERT_EQ(ret, 0);
    ASSERT_STREQ(array[0], "1234567890");
    ASSERT_EQ(array[1], nullptr);
    util_free_array(array);
    array = nullptr;

    ret = util_array_append(&array, "");
    ASSERT_EQ(ret, 0);
    ASSERT_STREQ(array[0], "");
    ASSERT_EQ(array[1], nullptr);
    util_free_array(array);
    array = nullptr;

    ret = util_array_append(&array, nullptr);
    ASSERT_NE(ret, 0);

    array_three = (char **)util_common_calloc_s(4 * sizeof(char *));
    ASSERT_NE(array_three, nullptr);
    array_three[0] = util_strdup_s("test1");
    array_three[1] = util_strdup_s("test2");
    array_three[2] = util_strdup_s("test3");
    array_three[3] = nullptr;
    ret = util_array_append(&array_three, "1234567890");
    ASSERT_EQ(ret, 0);
    ASSERT_STREQ(array_three[0], "test1");
    ASSERT_STREQ(array_three[1], "test2");
    ASSERT_STREQ(array_three[2], "test3");
    ASSERT_STREQ(array_three[3], "1234567890");
    ASSERT_EQ(array_three[4], nullptr);
    util_free_array(array_three);
    array_three = nullptr;

    ret = util_array_append(nullptr, "1234567890");
    ASSERT_NE(ret, 0);

    MOCK_SET(calloc, nullptr);
    ret = util_array_append(&array, "");
    ASSERT_NE(ret, 0);
    MOCK_CLEAR(calloc);
    util_free_array(array);
    array = nullptr;
}

TEST(utils_array, test_util_append_string_array)
{
    string_array *sarray = (string_array *)util_common_calloc_s(sizeof(string_array));
    ASSERT_NE(sarray, nullptr);
    int ret;

    ret = util_append_string_array(sarray, "1234567890");
    ASSERT_EQ(ret, 0);
    ASSERT_STREQ(sarray->items[0], "1234567890");
    ASSERT_EQ(sarray->items[1], nullptr);
    ASSERT_EQ(sarray->len, 1);

    ret = util_append_string_array(sarray, "abc");
    ASSERT_EQ(ret, 0);
    ret = util_append_string_array(sarray, "bcd");
    ASSERT_EQ(ret, 0);
    ASSERT_STREQ(sarray->items[1], "abc");
    ASSERT_STREQ(sarray->items[2], "bcd");
    ASSERT_EQ(sarray->len, 3);

    util_free_string_array(sarray);
    sarray = nullptr;
}

TEST(utils_array, test_util_copy_string_array)
{
    __isula_auto_string_array_t string_array *sarray_copy = nullptr;
    __isula_auto_string_array_t string_array *sarray = (string_array *)util_common_calloc_s(sizeof(string_array));
    ASSERT_NE(sarray, nullptr);
    int ret;

    ret = util_append_string_array(sarray, "1234567890");
    ASSERT_EQ(ret, 0);
    ret = util_append_string_array(sarray, "abc");
    ASSERT_EQ(ret, 0);
    ret = util_append_string_array(sarray, "bcd");
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(sarray->len, 3);

    sarray_copy = util_copy_string_array(sarray);
    ASSERT_NE(sarray_copy, nullptr);
    ASSERT_EQ(sarray_copy->len, sarray->len);
    for (size_t i = 0; i < sarray_copy->len; i++) {
        ASSERT_EQ(strcmp(sarray_copy->items[i], sarray->items[i]), 0);
    }

    ASSERT_EQ(util_copy_string_array(nullptr), nullptr);
    sarray->cap = 0;
    ASSERT_EQ(util_copy_string_array(sarray), nullptr);
    sarray->cap = sarray->len;
}

TEST(utils_array, test_util_string_array_contain)
{
    string_array *sarray = (string_array *)util_common_calloc_s(sizeof(string_array));
    ASSERT_NE(sarray, nullptr);
    int ret;
    bool bret = false;

    ret = util_append_string_array(sarray, "1234567890");
    ASSERT_EQ(ret, 0);
    ret = util_append_string_array(sarray, "abc");
    ASSERT_EQ(ret, 0);
    ret = util_append_string_array(sarray, "bcd");
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(sarray->len, 3);

    bret = util_string_array_contain(sarray, "axxx");
    ASSERT_EQ(bret, false);
    bret = util_string_array_contain(sarray, "abc");
    ASSERT_EQ(bret, true);

    util_free_string_array(sarray);
    sarray = nullptr;
}

TEST(utils_array, test_util_array_contain)
{
    char **array = nullptr;
    const char *element1 = "1234567890";
    const char *element2 = "abcdefghijk";

    ASSERT_EQ(util_array_contain(nullptr, element1), false);
    ASSERT_EQ(util_array_contain((const char **)array, nullptr), false);

    ASSERT_EQ(util_array_append(&array, element1), 0);
    ASSERT_EQ(util_array_contain((const char **)array, element1), true);
    ASSERT_EQ(util_array_contain((const char **)array, element2), false);

    ASSERT_EQ(util_array_append(&array, element2), 0);
    ASSERT_EQ(util_array_contain((const char **)array, element1), true);
    ASSERT_EQ(util_array_contain((const char **)array, element2), true);

    util_free_array(array);
    array = nullptr;
}

TEST(utils_array, test_util_common_array_append_pointer)
{
    int **array = nullptr;
    int *element1 = new int(12345);
    int *element2 = new int(678910);

    ASSERT_NE(util_common_array_append_pointer(nullptr, (void *)element1), 0);
    ASSERT_NE(util_common_array_append_pointer((void ***)&array, nullptr), 0);

    ASSERT_EQ(util_common_array_append_pointer((void ***)&array, (void *)element1), 0);
    ASSERT_EQ(array[0], element1);
    ASSERT_EQ(array[1], nullptr);


    ASSERT_EQ(util_common_array_append_pointer((void ***)&array, (void *)element2), 0);
    ASSERT_EQ(array[0], element1);
    ASSERT_EQ(array[1], element2);
    ASSERT_EQ(array[2], nullptr);

    free(array);
    array = nullptr;

    delete element1;
    delete element2;
}

static void common_array_free_mock(void *ptr)
{
    (void)ptr;
    return;
}

TEST(utils_array, test_util_append_common_array)
{
    __isula_auto_common_array_t common_array *carray = nullptr;
    int ret;
    int value1 = 1;
    int value2 = 2;
    int value3 = 3;

    carray = util_common_array_new(1, common_array_free_mock, util_clone_ptr);
    ASSERT_NE(carray, nullptr);

    ret = util_append_common_array(carray, &value1);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(carray->items[0], &value1);
    ASSERT_EQ(carray->len, 1);

    ret = util_append_common_array(carray, &value2);
    ASSERT_EQ(ret, 0);
    ret = util_append_common_array(carray, &value3);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(carray->items[1], &value2);
    ASSERT_EQ(carray->items[2], &value3);
    ASSERT_EQ(carray->len, 3);

    carray->clone_item_cb = nullptr;
    ASSERT_EQ(util_append_common_array(carray, &value1), -1);
    carray->clone_item_cb = util_clone_ptr;
    ASSERT_EQ(util_append_common_array(carray, nullptr), 0);
}

TEST(utils_array, test_util_merge_common_array)
{
    __isula_auto_common_array_t common_array *carray1 = nullptr;
    __isula_auto_common_array_t common_array *carray2 = nullptr;
    int ret;
    int value1 = 1;
    int value2 = 2;

    carray1 = util_common_array_new(1, common_array_free_mock, util_clone_ptr);
    ASSERT_NE(carray1, nullptr);
    carray2 = util_common_array_new(1, common_array_free_mock, util_clone_ptr);
    ASSERT_NE(carray2, nullptr);

    ret = util_append_common_array(carray1, &value1);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(carray1->items[0], &value1);
    ASSERT_EQ(carray1->len, 1);
    ret = util_append_common_array(carray2, &value2);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(carray2->items[0], &value2);
    ASSERT_EQ(carray2->len, 1);

    ret = util_merge_common_array(carray1, carray2);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(carray1->items[1], &value2);
    ASSERT_EQ(carray1->len, 2);

    ASSERT_EQ(util_merge_common_array(nullptr, carray2), -1);
    ASSERT_EQ(util_merge_common_array(carray1, nullptr), -1);
    carray1->clone_item_cb = nullptr;
    ASSERT_EQ(util_merge_common_array(carray1, carray2), -1);
    carray1->clone_item_cb = util_clone_ptr;
    carray2->clone_item_cb = nullptr;
    ASSERT_EQ(util_merge_common_array(carray1, carray2), -1);
    carray2->clone_item_cb = util_clone_ptr;
}