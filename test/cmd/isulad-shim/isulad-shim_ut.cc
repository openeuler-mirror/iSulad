/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * Description: isulad-shim unit test
 * Author: leizhongkai
 * Create: 2020-02-25
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "process.h"
#include "common.h"

int g_log_fd = -1;

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

class IsuladShimUnitTest : public testing::Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

TEST_F(IsuladShimUnitTest, test_new_process)
{
    string id = "aaaabbbbccccdddd";
    string bundle = "/home/isulad/bundle";
    string runtime = "kata-runtime";

    process_t *p = new_process((char*)id.c_str(), (char*)bundle.c_str(), (char*)runtime.c_str());
    ASSERT_TRUE(p == nullptr);
}

TEST_F(IsuladShimUnitTest, test_open_no_inherit)
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

TEST_F(IsuladShimUnitTest, test_read_write_nointr)
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

TEST_F(IsuladShimUnitTest, test_file_exist)
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


TEST_F(IsuladShimUnitTest, test_combined_output)
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
