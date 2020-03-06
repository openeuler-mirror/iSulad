/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wujing
 * Create: 2020-02-11
 * Description: syscall mock
 ******************************************************************************/


#ifndef SYSCALL_MOCK_H_
#define SYSCALL_MOCK_H_

#include <gmock/gmock.h>
#include <sys/vfs.h>

class MockSyscall {
public:
    virtual ~MockSyscall() = default;
    MOCK_METHOD2(Statfs, int(const char *path, struct statfs *buf));
};

void Syscall_SetMock(MockSyscall* mock);

#endif  // SYSCALL_MOCK_H_
