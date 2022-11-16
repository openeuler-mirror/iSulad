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
 * Description: provide mainloop mock
 ******************************************************************************/

#include "mainloop_mock.h"

namespace {
MockMainloop *g_mainloop_mock = nullptr;
}

void Mainloop_SetMock(MockMainloop* mock)
{
    g_mainloop_mock = mock;
}

int close(int fd)
{
    if (g_mainloop_mock != nullptr) {
        return g_mainloop_mock->Close(fd);
    }
    return 0;
}

int epoll_create1(int flags)
{
    std::cout << "epoll_create1" << std::endl;
    if (g_mainloop_mock != nullptr) {
        return g_mainloop_mock->EpollCreate1(flags);
    }
    return 0;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (g_mainloop_mock != nullptr) {
        return g_mainloop_mock->EpollCtl(epfd, op, fd, event);
    }
    return 0;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    if (g_mainloop_mock != nullptr) {
        return g_mainloop_mock->EpollWait(epfd, events, maxevents, timeout);
    }
    return 0;
}
