/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jikui
 * Create: 2020-02-14
 * Description: provide pause unit test
 ******************************************************************************/
#include "pause.h"
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

class ContainerPauseUnitTest : public testing::Test {
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
int ContainerPause(const struct isula_pause_request *request,
                   struct isula_pause_response *response, void *arg)
{
    (void)request;
    (void)arg;
    response->cc = 0;
    response->server_errono = 0;
    response->errmsg = nullptr;
    return 0;
}

int invokeGrpcOpsInit(isula_connect_ops *ops)
{
    if (ops == nullptr) {
        return -1;
    }
    ops->container.pause = &ContainerPause;
    return 0;
}

TEST_F(ContainerPauseUnitTest, test_cmd_pause_main)
{
    const char *argv[] = {"isula", "pause", "2e05a97d"};
    const char *argv_failure[] = {"isula", "pause", "-x"};

    EXPECT_CALL(m_grpcClient, GrpcOpsInit(_)).WillRepeatedly(Invoke(invokeGrpcOpsInit));
    ASSERT_EQ(connect_client_ops_init(), 0);
    EXPECT_EXIT(cmd_pause_main(sizeof(argv) / sizeof(argv[0]), const_cast<const char **>(argv)),
                testing::ExitedWithCode(0), "");
    EXPECT_EXIT(cmd_pause_main(sizeof(argv_failure) / sizeof(argv_failure[0]), const_cast<const char **>(argv_failure)),
                testing::ExitedWithCode(125), "Unknown flag found");
    testing::Mock::VerifyAndClearExpectations(&m_grpcClient);
}

