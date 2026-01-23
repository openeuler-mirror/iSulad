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

TEST_F(CommonUnitTest, test_get_attach_fifo_item)
{
    struct isula_linked_list *attach_fifos = NULL;
    attach_fifos = (struct isula_linked_list *)isula_common_calloc_s(sizeof(struct isula_linked_list));
    ASSERT_TRUE(attach_fifos != nullptr);

    isula_linked_list_init(attach_fifos);

    EXPECT_EQ(get_attach_fifo_item(4, attach_fifos), nullptr);
    EXPECT_EQ(get_attach_fifo_item(-1, attach_fifos), nullptr);
    EXPECT_EQ(get_attach_fifo_item(4, NULL), nullptr);

    struct shim_fifos_fd fifos1 = {
        .in_fd = 1,
        .out_fd = 2,
        .err_fd = 3,
    };
    struct shim_fifos_fd fifos2 = {
        .in_fd = 4,
        .out_fd = 5,
        .err_fd = 6,
    };
    struct isula_linked_list *node1 = NULL;
    struct isula_linked_list *node2 = NULL;
    node1 = (struct isula_linked_list *)isula_common_calloc_s(sizeof(struct isula_linked_list));
    ASSERT_TRUE(node1 != nullptr);
    node1->elem = &fifos1;
    isula_linked_list_add(attach_fifos, node1);

    node2 = (struct isula_linked_list *)isula_common_calloc_s(sizeof(struct isula_linked_list));
    ASSERT_TRUE(node2 != nullptr);
    node2->elem = &fifos2;
    isula_linked_list_add(attach_fifos, node2);

    EXPECT_EQ(get_attach_fifo_item(1, attach_fifos), node1);
    EXPECT_EQ(get_attach_fifo_item(4, attach_fifos), node2);

    free(node1);
    free(node2);
    free(attach_fifos);
}

TEST_F(CommonUnitTest, test_shim_append_error_message)
{
    shim_append_error_message("test for log");
    shim_set_error_message("test for log2");
    shim_append_error_message("test for log to clear last log");
}

TEST_F(CommonUnitTest, test_shim_set_error_message) {
    shim_set_error_message(nullptr);
    shim_set_error_message("test for log");
    shim_set_error_message("test for clear log in last time");
}

TEST_F(CommonUnitTest, test_isulad_shim_log_init) {
    const char *file = "fifo:\0";
    const char *file2 = "fifo:/tmp/not_exist_file";

    ASSERT_EQ(isulad_shim_log_init(nullptr, nullptr), -1);
    ASSERT_EQ(isulad_shim_log_init(file, "ERROR"), -1);
    ASSERT_EQ(isulad_shim_log_init(file2, "ERROR"), -1);
}

TEST_F(CommonUnitTest, test_free_shim_fifos_fd)
{
    struct shim_fifos_fd *fifos = NULL;
    fifos = (struct shim_fifos_fd *)isula_common_calloc_s(sizeof(*fifos));
    ASSERT_TRUE(fifos != nullptr);

    const char *in = "test";
    const char *out = "for";
    const char *err = "aaa";

    fifos->in_fifo = isula_strdup_s(in);
    fifos->out_fifo = isula_strdup_s(out);
    fifos->err_fifo = isula_strdup_s(err);
    fifos->in_fd = 1;
    fifos->out_fd = 2;
    fifos->err_fd = 3;

    free_shim_fifos_fd(fifos);
}