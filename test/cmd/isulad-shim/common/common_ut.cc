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
