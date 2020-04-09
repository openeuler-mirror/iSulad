/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2020-02-20
 * Description: provide info mock
 ******************************************************************************/
#include "info.h"
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

class InfoUnitTest : public testing::Test {
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

int Info(const struct isula_info_request *request,
         struct isula_info_response *response, void *arg)
{
    const char *driver_status = "Pool Name: isula-thinpool\n"
                                "Pool Blocksize: 524.3kB\n"
                                "Base Device Size: 10.74GB\n"
                                "Backing Filesystem: ext4\n"
                                "Data file: \n"
                                "Metadata file: \n"
                                "Data Space Used: 536.3MB\n"
                                "Data Space Total: 30.6GB\n"
                                "Data Space Available: 30.06GB\n"
                                "Metadata Space Used: 17.32MB\n"
                                "Metadata Space Total: 318.8MB\n"
                                "Metadata Space Available: 301.4MB\n"
                                "Thin Pool Minimum Free Space: 3.06GB\n"
                                "Udev Sync Supported: true\n"
                                "Deferred Removal Enabled: true\n"
                                "Deferred Deletion Enabled: true\n"
                                "Deferred Deleted Device Count: 0\n"
                                "Library Version: 1.02.150 (2018-08-01)\n"
                                "Semaphore Set Used: 0\n"
                                "Semaphore Set Total: 32000\n";

    response->driver_name = util_strdup_s("devicemapper");
    response->driver_status = util_strdup_s(driver_status);
    response->version = util_strdup_s("1.1.11");
    response->kversion = util_strdup_s("4.19.36-vhulk1904.3.1.h226.eulerosv2r8.aarch64");
    response->os_type = util_strdup_s("Linux");
    response->architecture = util_strdup_s("aarch64");
    response->nodename = NULL;
    response->operating_system = util_strdup_s("EulerOS 2.0 (SP8)");
    response->cgroup_driver = util_strdup_s("cgroupfs");
    response->logging_driver = util_strdup_s("json-file");
    response->huge_page_size = util_strdup_s("2MB");
    response->isulad_root_dir = util_strdup_s("/var/lib/isulad");
    response->http_proxy = NULL;
    response->https_proxy = NULL;
    response->no_proxy = NULL;
    response->errmsg = NULL;

    return 0;
}

int invokeGrpcOpsInit(isula_connect_ops *ops)
{
    if (ops == nullptr) {
        return -1;
    }
    ops->container.info = &Info;
    return 0;
}

TEST_F(InfoUnitTest, test_cmd_info_main_all)
{
    const char *argv[] = {"isula", "info"};
    const char *argv_failure[] = {"isula", "info", "-k"};
    isula_connect_ops ops;
    const char *driver_status = " Pool Name: isula-thinpool\n"
                                " Pool Blocksize: 524.3kB\n"
                                " Base Device Size: 10.74GB\n"
                                " Backing Filesystem: ext4\n"
                                " Data file: \n"
                                " Metadata file: \n"
                                " Data Space Used: 536.3MB\n"
                                " Data Space Total: 30.6GB\n"
                                " Data Space Available: 30.06GB\n"
                                " Metadata Space Used: 17.32MB\n"
                                " Metadata Space Total: 318.8MB\n"
                                " Metadata Space Available: 301.4MB\n"
                                " Thin Pool Minimum Free Space: 3.06GB\n"
                                " Udev Sync Supported: true\n"
                                " Deferred Removal Enabled: true\n"
                                " Deferred Deletion Enabled: true\n"
                                " Deferred Deleted Device Count: 0\n"
                                " Library Version: 1.02.150 (2018-08-01)\n"
                                " Semaphore Set Used: 0\n"
                                " Semaphore Set Total: 32000\n";

    ops.container.info = &Info;
    EXPECT_CALL(m_grpcClient, GrpcOpsInit(_))
    .WillOnce(Return(-1))
    .WillOnce(DoAll(SetArgPointee<0>(ByRef(ops)), Return(0)));
    ASSERT_EQ(connect_client_ops_init(), -1);
    ASSERT_EQ(connect_client_ops_init(), 0);
    EXPECT_EXIT(cmd_info_main(sizeof(argv) / sizeof(argv[0]), const_cast<const char **>(argv)),
                testing::ExitedWithCode(0), "");

    testing::internal::CaptureStdout();

    EXPECT_CALL(m_grpcClient, GrpcOpsInit(_)).WillRepeatedly(Invoke(invokeGrpcOpsInit));
    ASSERT_EQ(connect_client_ops_init(), 0);
    EXPECT_EXIT(cmd_info_main(sizeof(argv) / sizeof(argv[0]), const_cast<const char **>(argv)),
                testing::ExitedWithCode(0), "");
    EXPECT_EXIT(cmd_info_main(sizeof(argv_failure) / sizeof(argv_failure[0]), const_cast<const char **>(argv_failure)),
                testing::ExitedWithCode(125), "Unkown flag found");

    std::string output = testing::internal::GetCapturedStdout();
    if (output.find("devicemapper") == std::string::npos) {
        FAIL() << "isula info should contain devicemapper";
    }
    if (output.find(driver_status) == std::string::npos) {
        FAIL() << "isula info should contain driver status";
    }

    testing::Mock::VerifyAndClearExpectations(&m_grpcClient);
}
