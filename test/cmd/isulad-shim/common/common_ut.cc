/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: common unit test
 * Author: leizhongkai
 * Create: 2020-02-25
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "mock.h"

#include <isula_libutils/utils_memory.h>

#include "mainloop.h"
#include "process.h"
#include "common.h"

using ::testing::Args;
using ::testing::ByRef;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::NotNull;
using ::testing::AtLeast;
using ::testing::Invoke;
using ::testing::_;

using namespace std;

extern "C" {
    DECLARE_WRAPPER(calloc, void *, (size_t nmemb, size_t size));
    DEFINE_WRAPPER(calloc, void *, (size_t nmemb, size_t size), (nmemb, size));
}

class CommonUnitTest : public testing::Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

TEST(shim, test_signal_routine)
{
    signal_routine(SIGCONT);
}

TEST_F(CommonUnitTest, test_open_no_inherit)
{
    string exist_file = "/tmp/test_open_no_inherit_exist";
    string non_file = "/tmp/test_open_no_inherit_non";
    int fd_exist = -1;

    fd_exist = open_no_inherit(exist_file.c_str(), O_CREAT | O_WRONLY | O_APPEND | O_SYNC, 0640);
    EXPECT_GT(fd_exist, 0);
    EXPECT_EQ(open_no_inherit(non_file.c_str(), O_WRONLY, -1), -1);

    close(fd_exist);
    unlink(exist_file.c_str());
}

TEST_F(CommonUnitTest, test_read_write_nointr)
{
    char buf[32] = { 0 };
    string test_file = "/tmp/test_read_nointr";
    string test_string = "hello";
    int fd_wr = -1;
    int fd_rd = -1;
    int nwrite = -1;
    int nread = -1;

    EXPECT_EQ(read_nointr(-1, nullptr, 32), -1);
    EXPECT_EQ(read_nointr(0, nullptr, 32), -1);
    EXPECT_EQ(read_nointr(1, nullptr, 32), -1);

    fd_wr = open_no_inherit(test_file.c_str(), O_CREAT | O_RDWR | O_APPEND | O_SYNC, 0640);
    EXPECT_GT(fd_wr, 0);
    nwrite = write_nointr_in_total(fd_wr, test_string.c_str(), 5);
    EXPECT_EQ(nwrite, 5);
    fd_rd = open(test_file.c_str(), O_RDONLY);
    nread = read_nointr(fd_rd, buf, 32);
    EXPECT_EQ(nread, 5);

    close(fd_wr);
    close(fd_rd);
    unlink(test_file.c_str());
}

TEST_F(CommonUnitTest, test_file_exist)
{
    string exist_file = "/tmp/test_exist_exist";
    string non_file = "/tmp/test_exist_non";
    int fd_exist = -1;

    fd_exist = open_no_inherit(exist_file.c_str(), O_CREAT | O_WRONLY | O_APPEND | O_SYNC, 0640);
    EXPECT_GT(fd_exist, 0);
    EXPECT_TRUE(file_exists(exist_file.c_str()));
    EXPECT_FALSE(file_exists(non_file.c_str()));

    close(fd_exist);
    unlink(exist_file.c_str());
}


TEST_F(CommonUnitTest, test_combined_output)
{
    string exist_cmd = "ls";
    string non_cmd = "aaa";
    const char *params[MAX_RUNTIME_ARGS] = { nullptr };
    char output[BUFSIZ] = { 0 };
    int output_len = BUFSIZ;

    params[0] = exist_cmd.c_str();
    EXPECT_EQ(cmd_combined_output(exist_cmd.c_str(), params, output, &output_len), 0);

    params[0] = non_cmd.c_str();
    EXPECT_EQ(cmd_combined_output(non_cmd.c_str(), params, output, &output_len), -1);
}

TEST_F(CommonUnitTest, test_util_array_len)
{
    const char *array_long[] = { "abcd", "1234", "a1b", nullptr };

    ASSERT_EQ(util_array_len(nullptr), 0);

    ASSERT_EQ(util_array_len(array_long), 3);
}

TEST_F(CommonUnitTest, test_util_free_array)
{
    char **array = nullptr;

    array = (char **)isula_common_calloc_s(4 * sizeof(char *));
    ASSERT_NE(array, nullptr);
    array[0] = isula_strdup_s("test1");
    array[1] = isula_strdup_s("test2");
    array[2] = isula_strdup_s("test3");
    array[3] = nullptr;

    util_free_array(nullptr);
    util_free_array(array);
}

TEST(utils_array, test_util_grow_array)
{
    char **array = nullptr;
    size_t capacity = 0;
    int ret;

    capacity = 1;
    array = (char **)isula_common_calloc_s(sizeof(char *));
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
    array = (char **)isula_common_calloc_s(capacity * sizeof(char *));
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
    array = (char **)isula_common_calloc_s(capacity * sizeof(char *));
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
    array = (char **)isula_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(&array, &capacity, 1, 0);
    ASSERT_NE(ret, 0);
    util_free_array(array);
    array = nullptr;
    capacity = 0;

    capacity = 1;
    array = (char **)isula_common_calloc_s(capacity * sizeof(char *));
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
    array = (char **)isula_common_calloc_s(capacity * sizeof(char *));
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
    array = (char **)isula_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(&array, nullptr, 1, 1);
    ASSERT_NE(ret, 0);
    util_free_array(array);
    array = nullptr;
    capacity = 0;

    capacity = 1;
    array = (char **)isula_common_calloc_s(capacity * sizeof(char *));
    ASSERT_NE(array, nullptr);
    ret = util_grow_array(nullptr, &capacity, 1, 1);
    ASSERT_NE(ret, 0);
    util_free_array(array);
    array = nullptr;
    capacity = 0;
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