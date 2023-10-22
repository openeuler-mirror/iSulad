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

#include "service_container_api_mock.h"

namespace {
std::shared_ptr<MockServiceContainerApi> g_container_service_mock = nullptr;
}

void MockServiceContainerApi_SetMock(std::shared_ptr<MockServiceContainerApi> mock)
{
    g_container_service_mock = mock;
}

container_inspect *inspect_container(const char *id, int timeout, bool with_host_config)
{
    if (g_container_service_mock != nullptr) {
        return g_container_service_mock->InspectContainer(id, timeout, with_host_config);
    }
    return nullptr;
}
