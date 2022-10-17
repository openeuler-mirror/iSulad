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
 * Description: utils_network unit test
 * Author: zhangxiaoyu
 * Create: 2022-10-11
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "utils.h"
#include "utils_network.h"
#include "utils_network_mock.h"

using ::testing::NiceMock;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::_;

std::string GetLocalPath()
{
    char abs_path[PATH_MAX] { 0x00 };
    int ret = readlink("/proc/self/exe", abs_path, sizeof(abs_path));
    if (ret < 0 || static_cast<size_t>(ret) >= sizeof(abs_path)) {
        return "";
    }

    for (int i { ret }; i >= 0; --i) {
        if (abs_path[i] == '/') {
            abs_path[i + 1] = '\0';
            break;
        }
    }

    return static_cast<std::string>(abs_path);
}

class UtilsNetworkUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        UtilsNetwork_SetMock(&m_utils_network_mock);
        EXPECT_CALL(m_utils_network_mock, Mount(_, _, _, _, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(m_utils_network_mock, Umount2(_, _)).WillRepeatedly(Invoke(invokeUmont2));

        EXPECT_CALL(m_utils_network_mock, PthreadCreate(_, _, _, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(m_utils_network_mock, PthreadJoin(_, _)).WillRepeatedly(Invoke(invokePthreadJoin));
    }

    void TearDown() override
    {
        UtilsNetwork_SetMock(nullptr);
    }

    NiceMock<MockUtilsNetwork> m_utils_network_mock;

    static int invokeUmont2(const char *target, int flags)
    {
        errno = EINVAL;
        return -1;
    }

    static int invokePthreadJoin(pthread_t thread, void **retval)
    {
        void *status = (void *)calloc(1, sizeof(int));
        *retval = status;

        return 0;
    }
};

TEST_F(UtilsNetworkUnitTest, test_network_namespace)
{
    int err = 0;
    std::string netNS = GetLocalPath() + "test_namespace";

    ASSERT_EQ(util_create_netns_file(netNS.c_str()), 0);
    ASSERT_EQ(util_mount_namespace(netNS.c_str()), 0);
    ASSERT_EQ(util_umount_namespace(netNS.c_str()), 0);
    ASSERT_EQ(util_force_remove_file(netNS.c_str(), &err), true);
}
