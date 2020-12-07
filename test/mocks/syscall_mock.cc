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
 * Create: 2020-02-11
 * Description: provide syscall mock
 ******************************************************************************/

#include "syscall_mock.h"

namespace {
MockSyscall *g_syscall_mock = nullptr;
}

void Syscall_SetMock(MockSyscall* mock)
{
    g_syscall_mock = mock;
}

int statfs(const char *path, struct statfs *buf)
{
    if (g_syscall_mock != nullptr) {
        return g_syscall_mock->Statfs(path, buf);
    }
    return 0;
}