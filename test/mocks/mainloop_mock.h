/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2022-10-13
 * Description: mainloop mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_MAINLOOP_MOCK_H
#define _ISULAD_TEST_MOCKS_MAINLOOP_MOCK_H

#include <gmock/gmock.h>
#include <sys/epoll.h>

class MockMainloop {
public:
    virtual ~MockMainloop() = default;
    MOCK_METHOD1(Close, int(int));
    MOCK_METHOD1(EpollCreate1, int(int));
    MOCK_METHOD4(EpollCtl, int(int, int, int, struct epoll_event *));
    MOCK_METHOD4(EpollWait, int(int, struct epoll_event *, int, int));
};

void Mainloop_SetMock(MockMainloop* mock);

#endif // _ISULAD_TEST_MOCKS_MAINLOOP_MOCK_H
