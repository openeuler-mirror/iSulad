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
 * Description: provide sandboxes store mock
 ******************************************************************************/

#include "sandboxes_store_mock.h"

namespace {
    MockSandboxesStore *g_sandboxes_store_mock = nullptr;
}

void MockSandboxesStore_SetMock(MockSandboxesStore *mock)
{
    g_sandboxes_store_mock = mock;
}

int sandboxes_store_init(void)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxesStoreInit();
    }
    return -1;
}

bool sandboxes_store_add(const char *id, sandbox_t *sandbox)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxesStoreAdd(id, sandbox);
    }
    return false;
}

sandbox_t *sandboxes_store_get(const char *id_or_name)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxesStoreGet(id_or_name);
    }
    return nullptr;
}

sandbox_t *sandboxes_store_get_by_prefix(const char *prefix)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxesStoreGetByPrefix(prefix);
    }
    return nullptr;
}

bool sandboxes_store_remove(const char *id)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxesStoreRemove(id);
    }
    return false;
}

int sandbox_name_index_init(void)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxNameIndexInit();
    }
    return -1;
}

bool sandbox_name_index_remove(const char *name)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxNameIndexRemove(name);
    }
    return false;
}

char *sandbox_name_index_get(const char *name)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxNameIndexGet(name);
    }
    return nullptr;
}

bool sandbox_name_index_add(const char *name, const char *id)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxNameIndexAdd(name, id);
    }
    return false;
}

map_t *sandbox_name_index_get_all(void)
{
    if (g_sandboxes_store_mock != nullptr) {
        return g_sandboxes_store_mock->SandboxNameIndexGetAll();
    }
    return nullptr;
}
