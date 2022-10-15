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
 * Description: mainloop unit test
 * Author: zhangxiaoyu
 * Create: 2022-10-11
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mainloop.h"
#include "mainloop_mock.h"

using ::testing::NiceMock;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::_;

class MainloopUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        Mainloop_SetMock(&m_mainloop_mock);
        EXPECT_CALL(m_mainloop_mock, Close(_)).WillRepeatedly(Return(0));
        EXPECT_CALL(m_mainloop_mock, EpollCreate1(_)).WillRepeatedly(Return(0));
        EXPECT_CALL(m_mainloop_mock, EpollCtl(_, _, _, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(m_mainloop_mock, EpollWait(_, _, _, _)).WillRepeatedly(Return(0));
    }

    void TearDown() override
    {
        Mainloop_SetMock(nullptr);
    }

    NiceMock<MockMainloop> m_mainloop_mock;
};

TEST_F(MainloopUnitTest, test_mainloop)
{
    struct epoll_descr descr = { 0 };

    ASSERT_EQ(epoll_loop_open(&descr), 0);
    ASSERT_EQ(epoll_loop_add_handler(&descr, 111, nullptr, nullptr), 0);
    ASSERT_EQ(epoll_loop(&descr, -1), 0);
    ASSERT_EQ(epoll_loop_del_handler(&descr, 111), 0);
    ASSERT_EQ(epoll_loop_close(&descr), 0);
}
