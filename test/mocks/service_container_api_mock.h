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
 * Author: jikai
 * Create: 2023-10-20
 * Description: provide service container api mock
 ******************************************************************************/

#ifndef ISULAD_TEST_MOCKS_SERVICE_CONTAINER_API_MOCK_H
#define ISULAD_TEST_MOCKS_SERVICE_CONTAINER_API_MOCK_H

#include <gmock/gmock.h>
#include <memory>

#include "service_container_api.h"

class MockServiceContainerApi {
public:
    MOCK_METHOD3(InspectContainer, container_inspect *(const char *id, int timeout, bool with_host_config));
};

void MockServiceContainerApi_SetMock(std::shared_ptr<MockServiceContainerApi> mock);

#endif
