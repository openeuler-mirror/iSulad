/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
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
 * Description: provide containers store mock
 ******************************************************************************/

#include "containers_store_mock.h"

namespace {
MockContainersStore *g_containers_store_mock = NULL;
}

void MockContainersStore_SetMock(MockContainersStore *mock)
{
    g_containers_store_mock = mock;
}

int containers_store_init(void)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->ContainersStoreInit();
    }
    return -1;
}

bool containers_store_add(const char *id, container_t *cont)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->ContainersStoreAdd(id, cont);
    }
    return false;
}

container_t *containers_store_get(const char *id_or_name)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->ContainersStoreGet(id_or_name);
    }
    return nullptr;
}

container_t *containers_store_get_by_prefix(const char *prefix)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->ContainersStoreGetByPrefix(prefix);
    }
    return nullptr;
}

bool containers_store_remove(const char *id)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->ContainersStoreRemove(id);
    }
    return false;
}

int containers_store_list(container_t ***out, size_t *size)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->ContainersStoreList(out, size);
    }
    return -1;
}

char **containers_store_list_ids(void)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->ContainersStoreListIds();
    }
    return nullptr;
}

int container_name_index_init(void)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->NameIndexInit();
    }
    return -1;
}

bool container_name_index_remove(const char *name)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->NameIndexRemove(name);
    }
    return false;
}

char *container_name_index_get(const char *name)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->NameIndexGet(name);
    }
    return nullptr;
}

bool container_name_index_add(const char *name, const char *id)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->NameIndexAdd(name, id);
    }
    return false;
}

map_t *container_name_index_get_all(void)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->NameIndexGetAll();
    }
    return nullptr;
}

bool container_name_index_rename(const char *new_name, const char *old_name, const char *id)
{
    if (g_containers_store_mock != nullptr) {
        return g_containers_store_mock->NameIndexRename(new_name, old_name, id);
    }
    return false;
}
