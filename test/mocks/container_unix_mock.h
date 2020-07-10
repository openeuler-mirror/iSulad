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
 * Author: lifeng
 * Create: 2020-02-14
 * Description: provide container unix mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_CONTAINER_UNIX_MOCK_H
#define _ISULAD_TEST_MOCKS_CONTAINER_UNIX_MOCK_H

#include <gmock/gmock.h>
#include "container_unix.h"

class MockContainerUnix {
public:
    virtual ~MockContainerUnix() = default;
    MOCK_METHOD2(HasMountFor, bool(container_t *cont, const char *mpath));
    MOCK_METHOD1(ContainerToDisk, int(const container_t *cont));
    MOCK_METHOD1(ContainerUnlock, void(const container_t *cont));
    MOCK_METHOD1(ContainerLock, void(const container_t *cont));
    MOCK_METHOD1(ContainerUnref, void(container_t *cont));
    MOCK_METHOD2(ContainerUpdateRestartManager, void(container_t *cont, const host_config_restart_policy *policy));
};

void MockContainerUnix_SetMock(MockContainerUnix* mock);

#endif // _ISULAD_TEST_MOCKS_CONTAINER_UNIX_MOCK_H
