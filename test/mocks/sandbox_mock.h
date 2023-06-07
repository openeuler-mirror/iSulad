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
 * Description: provide sandbox mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_SANDBOX_MOCK_H
#define _ISULAD_TEST_MOCKS_SANDBOX_MOCK_H

#include <gmock/gmock.h>
#include "sandbox_api.h"

class MockSandbox {
public:
    virtual ~MockSandbox() = default;
    MOCK_METHOD1(SandboxUnlock, void(const sandbox_t *cont));
    MOCK_METHOD1(SandboxLock, void(const sandbox_t *cont));
    MOCK_METHOD1(SandboxUnref, void(sandbox_t *cont));
};

void MockSandbox_SetMock(MockSandbox *mock);

#endif // _ISULAD_TEST_MOCKS_SANDBOX_MOCK_H
