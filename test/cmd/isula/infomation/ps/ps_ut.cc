/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: ps unit test
 * Author: wujing
 * Create: 2019-12-19
 */
#include "ps.h"
#include <ctime>
#include <cmath>
#include <random>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "grpc_client_mock.h"
#include "utils.h"

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

class ContainerListUnitTest : public testing::Test {
public:
    void SetUp() override
    {
        GrpcClient_SetMock(&m_grpcClient);
        ::testing::Mock::AllowLeak(&m_grpcClient);
    }
    void TearDown() override
    {
        GrpcClient_SetMock(nullptr);
    }

    NiceMock<MockGrpcClient> m_grpcClient;
};

namespace {
unsigned generate_random_pid()
{
    constexpr int pid_start = 10000;
    constexpr int pid_end = 10000;
    static default_random_engine e(time(0));
    static uniform_int_distribution<unsigned> u(pid_start, pid_end);
    return u(e);
}

long long generate_random_created()
{
    // unix nanos: 2019-01-01T00:00:00.000000000+08:00
    constexpr int64_t start = 1546272000000000000ll;
    // unix nanos: 2019-12-31T00:00:00.000000000+08:00
    constexpr int64_t end = 1577721600000000000ll;

    static default_random_engine e(time(0));
    static uniform_int_distribution<long long> u(start, end);
    return u(e);
}

string generate_random_string(int length)
{
    static string chset = "abcdefghijklmnopqrstuvwxyz1234567890";
    string result;
    result.resize(length);

    srand(time(NULL));
    for (int i = 0; i < length; i++) {
        static default_random_engine e(time(0));
        static uniform_int_distribution<unsigned> u(0, chset.size() - 1);
        result[i] = chset[u(e) % chset.length()];
    }
    return result;
}

int set_container_summary(struct isula_list_response *response, int index)
{
    constexpr int id_len = 64;
    constexpr int name_len = 8;

    response->container_summary[index] = (struct isula_container_summary_info *)util_common_calloc_s(
                                             sizeof(struct isula_container_summary_info));
    if (response->container_summary[index] == nullptr) {
        return -1;
    }
    response->container_summary[index]->id = util_strdup_s(generate_random_string(id_len).c_str());
    response->container_summary[index]->name = util_strdup_s(generate_random_string(name_len).c_str());
    response->container_summary[index]->runtime = util_strdup_s("lcr");
    response->container_summary[index]->pid = generate_random_pid();
    response->container_summary[index]->status = (Container_Status)CONTAINER_STATUS_RUNNING;
    response->container_summary[index]->image = util_strdup_s("busybox:latest");
    response->container_summary[index]->command = util_strdup_s("/bin/sh");
    response->container_summary[index]->startat = util_strdup_s("2019-12-31T23:55:50.867369507+08:00");
    response->container_summary[index]->finishat = util_strdup_s("2020-01-01T23:55:50.867369507+08:00");
    response->container_summary[index]->exit_code = 0;
    response->container_summary[index]->restart_count = 0;
    response->container_summary[index]->created = generate_random_created();
    response->container_summary[index]->health_state = util_strdup_s("(healthy)");
    response->container_num++;

    return 0;
}
} // namespace

int ContainerList(const struct isula_list_request *request,
                  struct isula_list_response *response, void *arg)
{
    (void)request;
    (void)arg;
    constexpr int container_cnt = 5;
    response->cc = 0;
    response->server_errono = 0;
    response->errmsg = nullptr;
    response->container_summary = (struct isula_container_summary_info **)util_common_calloc_s(
                                      sizeof(struct isula_container_summary_info *) * container_cnt);
    if (response->container_summary == nullptr) {
        return -1;
    }
    for (size_t i {}; i < container_cnt; ++i) {
        if (set_container_summary(response, i)) {
            return -1;
        }
    }

    return 0;
}

int invokeGrpcOpsInit(isula_connect_ops *ops)
{
    if (ops == nullptr) {
        return -1;
    }
    ops->container.list = &ContainerList;
    return 0;
}

TEST_F(ContainerListUnitTest, test_cmd_list_main_all)
{
    const char *argv[] = {"isula", "ps", "-a"};
    const char *argv_failure[] = {"isula", "ps", "-k"};
    isula_connect_ops ops;

    ops.container.list = &ContainerList;
    EXPECT_CALL(m_grpcClient, GrpcOpsInit(_))
    .WillOnce(Return(-1))
    .WillOnce(DoAll(SetArgPointee<0>(ByRef(ops)), Return(0)));
    ASSERT_EQ(connect_client_ops_init(), -1);
    ASSERT_EQ(connect_client_ops_init(), 0);
    EXPECT_EXIT(cmd_list_main(sizeof(argv) / sizeof(argv[0]), const_cast<const char **>(argv)),
                testing::ExitedWithCode(0), "");

    EXPECT_CALL(m_grpcClient, GrpcOpsInit(_)).WillRepeatedly(Invoke(invokeGrpcOpsInit));
    ASSERT_EQ(connect_client_ops_init(), 0);
    EXPECT_EXIT(cmd_list_main(sizeof(argv) / sizeof(argv[0]), const_cast<const char **>(argv)),
                testing::ExitedWithCode(0), "");
    EXPECT_EXIT(cmd_list_main(sizeof(argv_failure) / sizeof(argv_failure[0]), const_cast<const char **>(argv_failure)),
                testing::ExitedWithCode(125), "Unkown flag found");
    testing::Mock::VerifyAndClearExpectations(&m_grpcClient);
}

TEST_F(ContainerListUnitTest, test_cmd_list_main_format)
{
    const char *argv[] = {
        "isula", "ps", "-a", "--format", "\"table XXX{{.ID}}AAA{{.Image}}"
        " {{.Status}} {{.Pid}} {{.Command}} {{.Created}} {{.Ports}} {{.ExitCode}} "
        "{{.RestartCount}} {{.StartAt}} {{.FinishAt}} {{.Runtime}} \t{{.Names}} \n{{.State}}\""
    };
    const char *argv_failure[] = {"isula", "ps", "--format", "\"{{.ID}} {{.XXX}}"};

    EXPECT_CALL(m_grpcClient, GrpcOpsInit(_)).WillRepeatedly(Invoke(invokeGrpcOpsInit));
    ASSERT_EQ(connect_client_ops_init(), 0);
    EXPECT_EXIT(cmd_list_main(sizeof(argv) / sizeof(argv[0]), const_cast<const char **>(argv)),
                testing::ExitedWithCode(0), "");
    EXPECT_EXIT(cmd_list_main(sizeof(argv_failure) / sizeof(argv_failure[0]), const_cast<const char **>(argv_failure)),
                testing::ExitedWithCode(1), "not support the field");
    testing::Mock::VerifyAndClearExpectations(&m_grpcClient);
}

TEST_F(ContainerListUnitTest, test_cmd_list_main_notrunc)
{
    const char *argv[] = {"isula", "ps", "-q", "--no-trunc"};
    testing::internal::CaptureStdout();

    EXPECT_CALL(m_grpcClient, GrpcOpsInit(_)).WillRepeatedly(Invoke(invokeGrpcOpsInit));
    ASSERT_EQ(connect_client_ops_init(), 0);
    EXPECT_EXIT(cmd_list_main(sizeof(argv) / sizeof(argv[0]), const_cast<const char **>(argv)),
                testing::ExitedWithCode(0), "");
    std::string output = testing::internal::GetCapturedStdout();
    if (output.find("CONTAINER ID") != std::string::npos) {
        ADD_FAILURE() << "the output of command('isula ps -q --no-trunc') should not  include table headers";
    }
    std::cout << "Gtest Captured Stdout:" << std::endl << output;
    testing::Mock::VerifyAndClearExpectations(&m_grpcClient);
}

TEST_F(ContainerListUnitTest, test_cmd_list_main_debug)
{
    const char *argv[] = {"isula", "ps", "-a", "-D"};
    testing::internal::CaptureStdout();

    EXPECT_CALL(m_grpcClient, GrpcOpsInit(_)).WillRepeatedly(Invoke(invokeGrpcOpsInit));
    ASSERT_EQ(connect_client_ops_init(), 0);
    EXPECT_EXIT(cmd_list_main(sizeof(argv) / sizeof(argv[0]), const_cast<const char **>(argv)),
                testing::ExitedWithCode(0), "");
    std::string output = testing::internal::GetCapturedStdout();
    std::vector<std::string> tableItems {"CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PORTS", "NAMES"};
    for (const auto &elem : tableItems) {
        if (output.find(elem) == std::string::npos) {
            ADD_FAILURE() << "container list info should include " << elem;
        }
    }
    if (output.find("healthy") == std::string::npos) {
        FAIL() << "container list info should include healthy";
    }
    std::cout << "Gtest Captured Stdout:" << std::endl << output;
    testing::Mock::VerifyAndClearExpectations(&m_grpcClient);
    SUCCEED() << "test isula ps --debug success";
}

