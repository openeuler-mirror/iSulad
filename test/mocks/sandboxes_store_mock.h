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
 * Description: provide sandbox store mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_SADNBOXES_STORE_MOCK_H
#define _ISULAD_TEST_MOCKS_SANDBOXES_STORE_MOCK_H

#include <gmock/gmock.h>
#include "sandbox_api.h"

class MockSandboxesStore {
public:
    virtual ~MockSandboxesStore() = default;
    MOCK_METHOD0(SandboxesStoreInit, int(void));
    MOCK_METHOD2(SandboxesStoreAdd, bool(const char *id, sandbox_t *sandbox));
    MOCK_METHOD1(SandboxesStoreGet, sandbox_t *(const char *id_or_name));
    MOCK_METHOD1(SandboxesStoreGetByPrefix, sandbox_t *(const char *prefix));
    MOCK_METHOD1(SandboxesStoreRemove, bool(const char *id));
    MOCK_METHOD0(SandboxNameIndexInit, int(void));
    MOCK_METHOD1(SandboxNameIndexRemove, bool(const char *name));
    MOCK_METHOD1(SandboxNameIndexGet, char *(const char *name));
    MOCK_METHOD2(SandboxNameIndexAdd, bool(const char *name, const char *id));
    MOCK_METHOD0(SandboxNameIndexGetAll, map_t * (void));
};

void MockSandboxesStore_SetMock(MockSandboxesStore *mock);

#endif // _ISULAD_TEST_MOCKS_SADNBOXES_STORE_MOCK_H
