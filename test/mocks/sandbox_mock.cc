/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-06-06
 * Description: provide sandbox unix mock
 ******************************************************************************/

#include "sandbox_mock.h"

namespace {
    MockSandbox *g_sandbox_mock = nullptr;
}

void MockSandbox_SetMock(MockSandbox *mock)
{
    g_sandbox_mock = mock;
}

/* sandbox unref */
void sandbox_unref(sandbox_t *cont)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->SandboxUnref(cont);
    }
    return;
}

void sandbox_unlock(sandbox_t *cont)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->SandboxUnlock(cont);
    }
}

void sandbox_lock(sandbox_t *cont)
{
    if (g_sandbox_mock != nullptr) {
        return g_sandbox_mock->SandboxLock(cont);
    }
}
