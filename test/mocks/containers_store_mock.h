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

#ifndef CONTAINERS_STORE_MOCK_H_
#define CONTAINERS_STORE_MOCK_H_

#include <gmock/gmock.h>
#include "container_api.h"

class MockContainersStore {
public:
    virtual ~MockContainersStore() = default;
    MOCK_METHOD0(ContainersStoreInit, int(void));
    MOCK_METHOD2(ContainersStoreAdd, bool(const char *id, container_t *cont));
    MOCK_METHOD1(ContainersStoreGet, container_t *(const char *id_or_name));
    MOCK_METHOD1(ContainersStoreGetByPrefix, container_t *(const char *prefix));
    MOCK_METHOD1(ContainersStoreRemove, bool(const char *id));
    MOCK_METHOD2(ContainersStoreList, int(container_t ***out, size_t *size));
    MOCK_METHOD0(ContainersStoreListIds, char **(void));
    MOCK_METHOD0(NameIndexInit, int(void));
    MOCK_METHOD1(NameIndexRemove, bool(const char *name));
    MOCK_METHOD1(NameIndexGet, char *(const char *name));
    MOCK_METHOD2(NameIndexAdd, bool(const char *name, const char *id));
    MOCK_METHOD0(NameIndexGetAll, map_t *(void));
    MOCK_METHOD3(NameIndexRename, bool(const char *new_name, const char *old_name, const char *id));
};

void MockContainersStore_SetMock(MockContainersStore *mock);

#endif // CONTAINERS_STORE_MOCK_H_