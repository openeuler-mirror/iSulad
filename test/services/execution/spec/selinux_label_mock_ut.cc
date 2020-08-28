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
 * Author: wujing
 * Create: 2020-02-14
 * Description: provide selinux label unit test
 ******************************************************************************/

#include "selinux_label.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "selinux_mock.h"
#include "syscall_mock.h"

using namespace std;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::ByRef;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::_;

class SELinuxGetEnableUnitTest : public testing::Test {
public:
    void SetUp() override
    {
        Selinux_SetMock(&m_selinux);
        Syscall_SetMock(&m_syscall);
        selinux_state_init();
    }
    void TearDown() override
    {
        Selinux_SetMock(nullptr);
        Syscall_SetMock(nullptr);
    }
    NiceMock<MockSelinux> m_selinux;
    NiceMock<MockSyscall> m_syscall;
};

TEST_F(SELinuxGetEnableUnitTest, test_selinux_get_enable_abnormal)
{
    EXPECT_CALL(m_syscall, Statfs(_, _)).WillRepeatedly(Return(EPERM));
    EXPECT_CALL(m_selinux, SelinuxfsExists()).WillOnce(Return(-1));
    ASSERT_EQ(selinux_get_enable(), false);
}
